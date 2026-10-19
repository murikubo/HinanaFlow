using System.Text;
namespace HinanaFlow.Core;
public sealed record TextEvent(string Kind, ControlMessage? Message = null, string? Text = null, int ByteCount = 0, int ScalarCount = 0);
public sealed class TextProtocol(bool authenticated)
{
    private sealed record Incoming(string Id, int Bytes, int Scalars, bool Accepted, double Deadline);
    private sealed record Outgoing(string Id, string Text, bool AwaitingReceipt, double Deadline);
    private Incoming? incoming;
    private Outgoing? outgoing;
    private readonly HashSet<string> seen = new(StringComparer.Ordinal);
    public bool HasOutgoing => outgoing is not null;
    public bool HasIncoming => incoming is not null;
    public bool NeedsConsent => incoming is not null && !incoming.Accepted;
    public bool Expired(double now) => incoming is not null && now >= incoming.Deadline || outgoing is not null && now >= outgoing.Deadline;
    private void Remember(string id)
    { if (!authenticated || seen.Count >= 1024 || !seen.Add(id)) throw new InvalidDataException("session"); }
    public ControlMessage Offer(string text, double now)
    {
        int count = ControlJson.ScalarCount(text), bytes = Encoding.UTF8.GetByteCount(text);
        if (!authenticated || Expired(now) || outgoing is not null || count is <1 or >8192 || bytes is <1 or >32768) throw new InvalidDataException("offer");
        var m = ControlMessage.Make("textOffer", new() {{"byteCount",bytes},{"scalarCount",count}});
        Remember(m.Id); outgoing = new(m.Id,text,false,now+60); return m;
    }
    public ControlMessage Decide(bool accept, double now)
    {
        var offer = incoming;
        if (!authenticated || Expired(now) || offer is null || offer.Accepted || now >= offer.Deadline) throw new InvalidDataException("decision");
        var m = ControlMessage.Make("decision", new() {{"offerId",offer.Id},{"accept",accept}});
        Remember(m.Id); incoming = accept ? offer with { Accepted=true, Deadline=now+10 } : null; return m;
    }
    public TextEvent[] Receive(ControlMessage m, double now)
    {
        if (Expired(now)) throw new InvalidDataException("timeout"); Remember(m.Id);
        switch (m.Type)
        {
            case "textOffer":
                int bytes=m.Integer("byteCount"), count=m.Integer("scalarCount");
                if (incoming is not null || bytes < count || bytes > count*4) throw new InvalidDataException("offer");
                incoming = new(m.Id,bytes,count,false,now+60); return [new("consent",ByteCount:bytes,ScalarCount:count)];
            case "decision":
                if (outgoing is null || outgoing.AwaitingReceipt || m.String("offerId") != outgoing.Id) throw new InvalidDataException("decision");
                if (!m.Boolean("accept")) { outgoing=null; return [new("denied")]; }
                var body=ControlMessage.Make("textData",new() {{"offerId",outgoing.Id},{"text",outgoing.Text}});
                Remember(body.Id); outgoing=outgoing with {AwaitingReceipt=true,Deadline=now+10}; return [new("send",body)];
            case "textData":
                if (incoming is null || !incoming.Accepted || m.String("offerId") != incoming.Id) throw new InvalidDataException("unapproved");
                string text=m.String("text");
                if (Encoding.UTF8.GetByteCount(text) != incoming.Bytes || ControlJson.ScalarCount(text) != incoming.Scalars) throw new InvalidDataException("size");
                var receipt=ControlMessage.Make("receipt",new() {{"offerId",incoming.Id}});
                Remember(receipt.Id); incoming=null; return [new("received",Text:text),new("send",receipt)];
            case "receipt":
                if (outgoing is null || !outgoing.AwaitingReceipt || m.String("offerId") != outgoing.Id) throw new InvalidDataException("receipt");
                outgoing=null; return [new("delivered")];
            case "cancel":
                string id=m.String("offerId");
                if (incoming?.Id==id) incoming=null; else if (outgoing?.Id==id) outgoing=null; else throw new InvalidDataException("cancel");
                return [new("denied")];
            default: throw new InvalidDataException("unsupported");
        }
    }
}
