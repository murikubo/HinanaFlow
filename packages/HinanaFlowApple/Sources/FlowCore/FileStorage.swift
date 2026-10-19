import Foundation
import CryptoKit
import Darwin

public enum FileTransferError:Error {case invalid,integrity,storage(Int32),expired}
public struct FileStorageSetupError:Error {
    public enum Stage:String,Sendable {case root,parent,create,open,attributes,protection}
    public let stage:Stage
    public let code:Int
}
private func ioCheck(_ result:Int32) throws {if result<0 {throw FileTransferError.storage(errno)}}
private func regular(_ fd:Int32) throws -> stat {
    var info=stat();try ioCheck(fstat(fd,&info))
    guard (info.st_mode & S_IFMT)==S_IFREG,info.st_nlink==1 else {throw FileTransferError.invalid}
    return info
}
private func writeAll(_ fd:Int32,_ data:Data) throws {
    try data.withUnsafeBytes {buffer in
        var offset=0
        while offset<buffer.count {
            let n=Darwin.write(fd,buffer.baseAddress!.advanced(by:offset),buffer.count-offset)
            if n<0 && errno==EINTR {continue}
            guard n>0 else {throw FileTransferError.storage(n<0 ? errno:EIO)}
            offset+=n
        }
    }
}
private func readBounded(_ fd:Int32,maximum:Int) throws -> Data {
    var result=Data(),buffer=[UInt8](repeating:0,count:32768)
    while true {
        let n=Darwin.read(fd,&buffer,buffer.count)
        if n<0 && errno==EINTR {continue}
        guard n>=0 else {throw FileTransferError.storage(errno)}
        if n==0 {return result}
        guard n<=maximum-result.count else {throw FileTransferError.invalid}
        result.append(contentsOf:buffer.prefix(n))
    }
}
/// A private, no-follow directory descriptor. Remote names never become filesystem paths.
public struct ReceivedFile:Identifiable,Sendable {
    public var id:URL {url}
    public let url:URL
    public let name:String
    public let size:Int
    public let sha256:String
}
private struct StoredMetadata:Codable {let name:String;let size:Int;let sha256:String}
public final class TransferStorage {
    fileprivate let fd:Int32
    public let directory:URL
    public init(directory:URL) throws {
        // The base is an OS app-container URL (or a caller-owned test directory), never remote input.
        // The last component and every operation beneath it reject symbolic links.
        self.directory=directory
        guard directory.isFileURL,directory.path.hasPrefix("/"),!directory.lastPathComponent.isEmpty else {throw FileTransferError.invalid}
        var parent=open("/",O_SEARCH|O_NOFOLLOW|O_CLOEXEC)
        guard parent>=0 else {throw FileStorageSetupError(stage:.root,code:Int(errno))}
        defer {close(parent)}
        for component in directory.deletingLastPathComponent().pathComponents.dropFirst() {
            guard component != ".",component != ".." else {throw FileTransferError.invalid}
            let next=openat(parent,component,O_SEARCH|O_NOFOLLOW|O_CLOEXEC)
            guard next>=0 else {throw FileStorageSetupError(stage:.parent,code:Int(errno))}
            close(parent);parent=next
        }
        fd=try Self.openPrivateLeaf(parent:parent,leaf:directory.lastPathComponent)
    }
    /// Anchor supplied ONLY by FileManager's OS app-container Application Support URL.
    /// System-managed ancestors may contain links; no remote/user path is accepted here.
    public init(appSupportDirectory base:URL,profile:ValidationProfile = .production) throws {
        guard base.isFileURL,base.path.hasPrefix("/") else {throw FileTransferError.invalid}
        directory=base.appendingPathComponent(profile.transferDirectory,isDirectory:true)
        let anchor=open(base.path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)
        guard anchor>=0 else {throw FileStorageSetupError(stage:.parent,code:Int(errno))}
        defer {close(anchor)}
        var info=stat()
        guard fstat(anchor,&info)==0,info.st_uid==getuid() else {throw FileStorageSetupError(stage:.attributes,code:0)}
        fd=try Self.openPrivateLeaf(parent:anchor,leaf:profile.transferDirectory)
    }
    private static func openPrivateLeaf(parent:Int32,leaf:String) throws -> Int32 {
        if mkdirat(parent,leaf,0o700)<0 && errno != EEXIST {throw FileStorageSetupError(stage:.create,code:Int(errno))}
        let opened=openat(parent,leaf,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)
        guard opened>=0 else {throw FileStorageSetupError(stage:.open,code:Int(errno))}
        var s=stat()
        if fstat(opened,&s)<0 || s.st_uid != getuid() || (s.st_mode & 0o077) != 0 {
            close(opened);throw FileStorageSetupError(stage:.attributes,code:0)
        }
        return opened
    }
    deinit {close(fd)}
    fileprivate func temporary() throws -> (Int32,String) {
        let name=".hf-stage-"+UUID().uuidString.lowercased()+".part"
        let file=openat(fd,name,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0o600)
        guard file>=0 else {throw FileTransferError.storage(errno)}
        #if os(iOS)
        do {try FileManager.default.setAttributes([.protectionKey:FileProtectionType.complete],ofItemAtPath:directory.appendingPathComponent(name).path)}
        catch {close(file);unlinkat(fd,name,0);throw FileStorageSetupError(stage:.protection,code:(error as NSError).code)}
        #endif
        return (file,name)
    }
    /// Own namespace only. Called before any live transfer, never while another session uses this store.
    public func recoverOrphans() throws {
        let copy=openat(fd,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);guard copy>=0 else {throw FileTransferError.storage(errno)}
        guard let dir=fdopendir(copy) else {close(copy);throw FileTransferError.storage(errno)}
        defer {closedir(dir)}
        while let item=readdir(dir) {
            let name=withUnsafePointer(to:&item.pointee.d_name) {p in p.withMemoryRebound(to:CChar.self,capacity:Int(NAME_MAX)+1) {String(cString:$0)}}
            if name.hasPrefix("received-"),name.hasSuffix(".bin.json"),
               UUID(uuidString:String(name.dropFirst(9).dropLast(9))) != nil {
                let dataName=String(name.dropLast(5));var dataInfo=stat(),metaInfo=stat()
                if fstatat(fd,dataName,&dataInfo,AT_SYMLINK_NOFOLLOW)<0 && errno==ENOENT,
                   fstatat(fd,name,&metaInfo,AT_SYMLINK_NOFOLLOW)==0,(metaInfo.st_mode & S_IFMT)==S_IFREG,
                   metaInfo.st_uid==getuid(),metaInfo.st_nlink==1 {try ioCheck(unlinkat(fd,name,0))}
                continue
            }
            guard name.hasPrefix(".hf-stage-"),name.hasSuffix(".part"),
                  UUID(uuidString:String(name.dropFirst(10).dropLast(5))) != nil else {continue}
            var s=stat()
            if fstatat(fd,name,&s,AT_SYMLINK_NOFOLLOW)==0,(s.st_mode & S_IFMT)==S_IFREG {try ioCheck(unlinkat(fd,name,0))}
        }
    }
    public func verifiedFiles() throws -> [URL] {
        try FileManager.default.contentsOfDirectory(at:directory,includingPropertiesForKeys:nil).filter {url in
            guard url.lastPathComponent.hasPrefix("received-"),url.pathExtension=="bin" else {return false}
            var s=stat()
            return fstatat(fd,url.lastPathComponent,&s,AT_SYMLINK_NOFOLLOW)==0 && (s.st_mode & S_IFMT)==S_IFREG && s.st_nlink==1 && s.st_size<=FileTransfer.maximumSize
        }.sorted {$0.lastPathComponent<$1.lastPathComponent}
    }
    public func receivedFiles() throws -> [ReceivedFile] {
        try verifiedFiles().compactMap {url in
            let name=url.lastPathComponent
            guard UUID(uuidString:String(name.dropFirst(9).dropLast(4))) != nil else {return nil}
            let meta=openat(fd,name+".json",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)
            guard meta>=0 else {return nil};defer {close(meta)}
            let info=try regular(meta);guard (1...2048).contains(info.st_size) else {throw FileTransferError.invalid}
            let bytes=try readBounded(meta,maximum:2048)
            let m=try JSONDecoder().decode(StoredMetadata.self,from:bytes)
            guard SharedFilename.valid(m.name),(0...FileTransfer.maximumSize).contains(m.size),
                  m.sha256.count==64,m.sha256.allSatisfy({$0.isHexDigit && !$0.isUppercase}) else {throw FileTransferError.invalid}
            return ReceivedFile(url:url,name:m.name,size:m.size,sha256:m.sha256)
        }
    }
    /// Explicit export reads only our verified generated path; never follows a changed file or metadata link.
    public func export(_ selected:ReceivedFile) throws -> Data {
        guard let current=try receivedFiles().first(where:{$0.url==selected.url}),
              current.name==selected.name,current.size==selected.size,current.sha256==selected.sha256 else {throw FileTransferError.invalid}
        let file=openat(fd,current.url.lastPathComponent,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)
        guard file>=0 else {throw FileTransferError.storage(errno)};defer {close(file)}
        let info=try regular(file);guard info.st_size==current.size else {throw FileTransferError.integrity}
        let data=try readBounded(file,maximum:FileTransfer.maximumSize)
        guard data.count==current.size,SHA256.hash(data:data).map({String(format:"%02x",$0)}).joined()==current.sha256 else {throw FileTransferError.integrity}
        return data
    }

}
public final class FileSnapshot {
    private let storage:TransferStorage
    private let fd:Int32
    private let temporaryName:String
    public let size:Int
    public let sha256:String
    public let name:String
    private var offset=0
    public init(source:URL,name:String?=nil,storage:TransferStorage) throws {
        let sourceFD=open(source.path,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)
        guard sourceFD>=0 else {throw FileTransferError.storage(errno)}
        defer {close(sourceFD)}
        let info=try regular(sourceFD)
        guard info.st_size>=0,info.st_size<=FileTransfer.maximumSize else {throw FileTransferError.invalid}
        let (file,temp)=try storage.temporary()
        var complete=false
        defer {if !complete {close(file);unlinkat(storage.fd,temp,0)}}
        var count=0,hash=SHA256();var buffer=[UInt8](repeating:0,count:FileChunk.maximumData)
        while true {
            let n=Darwin.read(sourceFD,&buffer,buffer.count)
            if n<0 && errno==EINTR {continue}
            guard n>=0 else {throw FileTransferError.storage(errno)}
            if n==0 {break}
            count+=n;guard count<=FileTransfer.maximumSize else {throw FileTransferError.invalid}
            let data=Data(buffer.prefix(n));try writeAll(file,data);hash.update(data:data)
        }
        guard count==Int(info.st_size) else {throw FileTransferError.invalid}
        try ioCheck(fsync(file));guard lseek(file,0,SEEK_SET)==0 else {throw FileTransferError.storage(errno)}
        let digest=hash.finalize().map {String(format:"%02x",$0)}.joined(),advertisedName=try SharedFilename.normalize(name ?? source.lastPathComponent)
        _=try ControlMessage.make("fileOfferUnicode",["name":.string(advertisedName),"size":.integer(count),"sha256":.string(digest)])
        self.storage=storage;fd=file;temporaryName=temp;size=count;sha256=digest;self.name=advertisedName
        complete=true
    }
    private init(storage:TransferStorage,descriptor:Int32,temporaryName:String,size:Int,sha256:String) {
        self.storage=storage;fd=descriptor;self.temporaryName=temporaryName;self.size=size;self.sha256=sha256;name="diagnostic.bin"
    }
    public static func diagnostic(storage:TransferStorage) throws -> FileSnapshot {
        let (fd,name)=try storage.temporary();var completed=false
        defer {if !completed {close(fd);unlinkat(storage.fd,name,0)}}
        let chunk=Data((0..<FileChunk.maximumData).map {UInt8(truncatingIfNeeded:$0)})
        var hash=SHA256()
        for _ in 0..<8 {try writeAll(fd,chunk);hash.update(data:chunk)}
        try ioCheck(fsync(fd));guard lseek(fd,0,SEEK_SET)==0 else {throw FileTransferError.storage(errno)}
        let result=FileSnapshot(storage:storage,descriptor:fd,temporaryName:name,size:262144,sha256:hash.finalize().map {String(format:"%02x",$0)}.joined())
        completed=true;return result
    }
    deinit {close(fd);unlinkat(storage.fd,temporaryName,0)}
    public func next() throws -> Data? {
        guard offset<size else {return nil}
        var buffer=[UInt8](repeating:0,count:min(FileChunk.maximumData,size-offset))
        let n=Darwin.read(fd,&buffer,buffer.count)
        guard n>0 else {throw FileTransferError.storage(n<0 ? errno:EIO)}
        offset+=n;return Data(buffer.prefix(n))
    }
}
public final class IncomingFile {
    private let storage:TransferStorage
    private var fd:Int32
    private let temporaryName:String
    private let expectedSize:Int
    private let expectedHash:String
    private var bytes=0,hash=SHA256()
    private let writeBudget:Int
    /// writeBudget permits deterministic quota-failure testing; normal app receives use the full cap.
    public init(storage:TransferStorage,size:Int,sha256:String,writeBudget:Int=FileTransfer.maximumSize) throws {
        guard (0...FileTransfer.maximumSize).contains(size),(0...FileTransfer.maximumSize).contains(writeBudget),sha256.count==64 else {throw FileTransferError.invalid}
        self.storage=storage;expectedSize=size;expectedHash=sha256;self.writeBudget=writeBudget
        let pair=try storage.temporary();fd=pair.0;temporaryName=pair.1
    }
    deinit {abort()}
    public func abort() {if fd>=0 {close(fd);fd = -1};unlinkat(storage.fd,temporaryName,0)}
    public func append(offset:Int,data:Data) throws {
        guard fd>=0,offset==bytes,!data.isEmpty,data.count<=FileChunk.maximumData,data.count<=expectedSize-bytes else {throw FileTransferError.invalid}
        guard data.count<=writeBudget-bytes else {throw FileTransferError.storage(ENOSPC)}
        try writeAll(fd,data);hash.update(data:data);bytes+=data.count
    }
    public func finish(finalName:String,displayName:String?=nil) throws -> URL {
        guard fd>=0,bytes==expectedSize,hash.finalize().map({String(format:"%02x",$0)}).joined()==expectedHash else {throw FileTransferError.integrity}
        guard finalName.hasPrefix("received-"),finalName.hasSuffix(".bin"),UUID(uuidString:String(finalName.dropFirst(9).dropLast(4))) != nil else {throw FileTransferError.invalid}
        let info=try regular(fd);guard info.st_size==expectedSize else {throw FileTransferError.integrity}
        try ioCheck(fsync(fd));try ioCheck(fchmod(fd,0o400))
        // Both published names are generated. A metadata orphan alone is never a completed file.
        let metadataName=finalName+".json"
        var ownMetadata=false,ownFinal=false,committed=false
        defer {
            if !committed {
                if ownFinal {unlinkat(storage.fd,finalName,0)}
                if ownMetadata {unlinkat(storage.fd,metadataName,0)}
            }
        }
        if let displayName {
            guard SharedFilename.valid(displayName) else {throw FileTransferError.invalid}
            let metadata=StoredMetadata(name:displayName,size:expectedSize,sha256:expectedHash)
            let (meta,temp)=try storage.temporary()
            defer {close(meta);unlinkat(storage.fd,temp,0)}
            try writeAll(meta,try JSONEncoder().encode(metadata));try ioCheck(fsync(meta));try ioCheck(fchmod(meta,0o400))
            try ioCheck(linkat(storage.fd,temp,storage.fd,metadataName,0));ownMetadata=true
        }
        try ioCheck(linkat(storage.fd,temporaryName,storage.fd,finalName,0));ownFinal=true
        try ioCheck(unlinkat(storage.fd,temporaryName,0));try ioCheck(fsync(storage.fd))
        committed=true
        close(fd);fd = -1
        return storage.directory.appendingPathComponent(finalName)
    }
}
