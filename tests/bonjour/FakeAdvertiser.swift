// Opt-in, bounded real-LAN negative fixture. Not part of either application target.
// Two unauthenticated advertisements ask for the same generic name; Bonjour handles collision naming.
// No TLS identity, files, TXT, or application-body reads. Every incoming connection is cancelled.
import Foundation
import Network
import Darwin
let parameters=NWParameters.tcp
parameters.requiredInterfaceType = .wifi
parameters.includePeerToPeer=false
parameters.prohibitedInterfaceTypes=[.cellular,.loopback,.other]
let listeners=try (0..<2).map {_ -> NWListener in
    let l=try NWListener(using:parameters,on:.any)
    l.service=NWListener.Service(name:"HF-Untrusted-Test",type:"_hinanaflow._tcp",domain:"local.",txtRecord:nil)
    l.newConnectionHandler = {$0.cancel()}
    l.start(queue:.main)
    return l
}
print("Bounded fake advertisements started; no authenticated transport or body handler")
DispatchQueue.main.asyncAfter(deadline:.now()+60) {listeners.forEach {$0.cancel()};exit(0)}
dispatchMain()
