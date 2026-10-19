import Foundation

/// Wire names are metadata only; internal paths always use generated UUIDs.
public enum SharedFilename {
    public static func normalize(_ name:String) throws -> String {
        let n=name.precomposedStringWithCanonicalMapping
        guard valid(n) else {throw FileTransferError.invalid};return n
    }
    public static func valid(_ name:String) -> Bool {
        guard name.utf8.elementsEqual(name.precomposedStringWithCanonicalMapping.utf8),
              !name.isEmpty,name.unicodeScalars.count<=120,name.utf8.count<=180,
              !name.hasPrefix("."),!name.hasPrefix(" "),!name.hasSuffix("."),!name.hasSuffix(" "),!name.contains("..") else {return false}
        let forbidden=CharacterSet(charactersIn:"/\\:<>\"|?*")
        for scalar in name.unicodeScalars {
            if forbidden.contains(scalar) {return false}
            switch scalar.properties.generalCategory {
            case .control,.format,.lineSeparator,.paragraphSeparator,.surrogate,.privateUse,.unassigned:return false
            default:break
            }
            if scalar.properties.isWhitespace && scalar.value != 32 {return false}
        }
        let stem=String(name.split(separator:".",omittingEmptySubsequences:false)[0]).trimmingCharacters(in:CharacterSet(charactersIn:" ")).uppercased()
        let reserved=["CON","PRN","AUX","NUL","CLOCK$","CONIN$","CONOUT$"]+(1...9).flatMap {["COM\($0)","LPT\($0)"]}+["COM¹","COM²","COM³","LPT¹","LPT²","LPT³"]
        return !reserved.contains(stem)
    }
}
