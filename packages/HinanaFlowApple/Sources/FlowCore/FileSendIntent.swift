import Foundation

/// A user's one-shot send action is bound to the exact staged selection, never a discovery name.
public struct FileSendIntent:Sendable {
    private var selection:UUID?
    public init() {}
    public mutating func approve(selection:UUID) {self.selection=selection}
    public mutating func clear() {selection=nil}
    public mutating func consume(selection:UUID?,authenticated:Bool) -> Bool {
        let approved=self.selection;self.selection=nil
        return authenticated && approved != nil && approved==selection
    }
}
