using System.Text.Json;
using System.Security.Cryptography;
using HinanaFlow.Core;

if (args.Length != 1) throw new ArgumentException("Pass protocol/vectors.json");
using var document = JsonDocument.Parse(File.ReadAllText(args[0]));
int checkedCases = 0;
foreach (var vector in document.RootElement.GetProperty("frames").EnumerateArray())
{
    var bytes = Convert.FromHexString(vector.GetProperty("hex").GetString()!);
    bool valid = vector.GetProperty("valid").GetBoolean();
    for (int split = 0; split <= bytes.Length; split++)
    {
        var decoder = new ControlDecoder();
        try
        {
            var frames = decoder.Feed(bytes.AsSpan(0, split));
            frames.AddRange(decoder.Feed(bytes.AsSpan(split))); decoder.Finish();
            if (!valid) throw new Exception("invalid frame accepted");
            var expected = Convert.FromHexString(vector.GetProperty("payloadHex").GetString()!);
            if (frames.Count != 1 || !frames[0].SequenceEqual(expected)) throw new Exception("payload mismatch");
        }
        catch (InvalidDataException) { if (valid) throw; }
        checkedCases++;
    }
}
foreach (var vector in document.RootElement.GetProperty("sha256").EnumerateArray())
{
    var digest = SHA256.HashData(Convert.FromHexString(vector.GetProperty("inputHex").GetString()!));
    if (!Convert.ToHexString(digest).Equals(vector.GetProperty("digest").GetString(), StringComparison.OrdinalIgnoreCase)) throw new Exception("hash mismatch");
}
foreach (var vector in document.RootElement.GetProperty("pins").EnumerateArray())
{
    var key = Convert.FromHexString(vector.GetProperty("publicKeyHex").GetString()!);
    using var ecdsa = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256,
        Q = new ECPoint { X = key[1..33], Y = key[33..65] } });
    // Public-key digest matches both platforms; no private key or key-store lookup.
    if (!Convert.ToHexString(SHA256.HashData(key)).Equals(vector.GetProperty("sha256").GetString(), StringComparison.OrdinalIgnoreCase)) throw new Exception("pin mismatch");
}
foreach (bool trusted in new[] { false, true }) foreach (bool approved in new[] { false, true })
    if (TransferGate.Authorize(trusted, approved)) throw new Exception("transfer gate open");
Console.WriteLine($"PASS: {checkedCases} frame split cases; shared hash/pin vectors; closed transfer gate");

int jsonCases = 0;
foreach (var v in document.RootElement.GetProperty("control").EnumerateArray())
{
    bool accepted = true;
    try { ControlJson.Parse(Convert.FromHexString(v.GetProperty("inputHex").GetString()!)); }
    catch (InvalidDataException) { accepted = false; }
    if (accepted != v.GetProperty("valid").GetBoolean()) throw new Exception("JSON vector failed: " + v.GetProperty("name").GetString());
    jsonCases++;
}
foreach (var v in document.RootElement.GetProperty("controlBytes").EnumerateArray())
{
    try { ControlJson.Parse(Convert.FromHexString(v.GetProperty("hex").GetString()!)); throw new Exception("invalid UTF8 accepted"); }
    catch (InvalidDataException) { }
}
Console.WriteLine($"PASS: {jsonCases} native C# JSON cases and invalid UTF8 vectors");

static ControlMessage Sent(TextEvent[] events) => events.Single(e=>e.Kind=="send").Message!;
static void Exchange(TextProtocol sender, TextProtocol receiver, string text, double now)
{
    var offer=sender.Offer(text,now);
    if(offer.Fields.ContainsKey("text")) throw new Exception("offer contains body");
    var consent=receiver.Receive(ControlJson.Parse(offer.Encode()),now+1);
    if(consent.Single().Kind!="consent") throw new Exception("missing consent");
    var decision=receiver.Decide(true,now+2);
    var body=Sent(sender.Receive(ControlJson.Parse(decision.Encode()),now+3));
    var received=receiver.Receive(ControlJson.Parse(body.Encode()),now+4);
    if(received.Single(e=>e.Kind=="received").Text!=text) throw new Exception("text mismatch");
    if(sender.Receive(ControlJson.Parse(Sent(received).Encode()),now+5).Single().Kind!="delivered") throw new Exception("receipt");
}
static void MustReject(Action operation)
{
    try {operation();} catch(InvalidDataException) {return;}
    throw new Exception("expected rejection");
}
var a=new TextProtocol(true); var b=new TextProtocol(true);
Exchange(a,b,"Windows → macOS 👋",0); Exchange(b,a,"macOS → Windows 안녕",10);
MustReject(()=>new TextProtocol(false).Offer("blocked",0));
var c=new TextProtocol(true); var d=new TextProtocol(true);
var offer=c.Offer("secret",0); d.Receive(offer,1);
MustReject(()=>d.Receive(ControlMessage.Make("textData",new() {{"offerId",offer.Id},{"text","secret"}}),2));
var denyA=new TextProtocol(true); var denyB=new TextProtocol(true);
var deniedOffer=denyA.Offer("not delivered",0); denyB.Receive(deniedOffer,1);
if(denyA.Receive(denyB.Decide(false,2),3).Any(e=>e.Kind=="send")) throw new Exception("body after deny");
MustReject(()=>denyB.Receive(deniedOffer,4));
var timed=new TextProtocol(true); timed.Offer("timeout",0); if(!timed.Expired(60)) throw new Exception("timeout");
var sizeA=new TextProtocol(true);var sizeB=new TextProtocol(true);var sizeOffer=sizeA.Offer("abc",0);
sizeB.Receive(sizeOffer,1);sizeB.Decide(true,2);
MustReject(()=>sizeB.Receive(ControlMessage.Make("textData",new() {{"offerId",sizeOffer.Id},{"text","abcd"}}),3));
if(!LanBinding.SharesSubnet(System.Net.IPAddress.Parse("192.168.1.10"),System.Net.IPAddress.Parse("192.168.1.11"),System.Net.IPAddress.Parse("255.255.255.0"))) throw new Exception("subnet");
Console.WriteLine("PASS: bidirectional consent/receipt and unpaired/pre-consent/denial/replay/timeout/size checks");

Exchange(a,b,"\ufeffa\u0301👋",20);
var dualA=new TextProtocol(true);var dualB=new TextProtocol(true);
var offerA=dualA.Offer("A",0);var offerB=dualB.Offer("B",0);
dualA.Receive(offerB,1);dualB.Receive(offerA,1);
var decisionA=dualA.Decide(true,2);var decisionB=dualB.Decide(true,2);
var bodyA=Sent(dualA.Receive(decisionB,3));var bodyB=Sent(dualB.Receive(decisionA,3));
var responseA=dualA.Receive(bodyB,4);var responseB=dualB.Receive(bodyA,4);
dualA.Receive(Sent(responseB),5);dualB.Receive(Sent(responseA),5);
if(dualA.HasOutgoing || dualB.HasOutgoing) throw new Exception("simultaneous completion");
MustReject(()=>new TextProtocol(true).Receive(ControlMessage.Make("fileOffer",new() {{"name","a.txt"},{"size",0},{"sha256",new string('0',64)}}),0));
Console.WriteLine("PASS: encode/decode body preservation, simultaneous bidirectional offers, blocked file offer");

var consentA=new TextProtocol(true);var consentB=new TextProtocol(true);
var ca=consentA.Offer("A",0);var cb=consentB.Offer("B",0);
consentA.Receive(cb,1);consentB.Receive(ca,1);consentA.Decide(true,2);
consentA.Receive(ControlMessage.Make("cancel",new() {{"offerId",ca.Id}}),3);
if(!consentA.HasIncoming || consentA.NeedsConsent) throw new Exception("cancel changed consent");
Console.WriteLine("PASS: cancellation preserves opposite-direction consent state");
