using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
namespace HinanaFlow.Core;

public sealed record ControlMessage(Dictionary<string, JsonElement> Fields)
{
    public string String(string key) => Fields[key].GetString() ?? throw new InvalidDataException("invalid_json");
    public int Integer(string key) => Fields[key].GetInt32();
    public bool Boolean(string key) => Fields[key].GetBoolean();
    public string Type => String("type");
    public string Id => String("id");
    public byte[] Encode() { var data = JsonSerializer.SerializeToUtf8Bytes(Fields); ControlJson.Parse(data); return data; }
    public static ControlMessage Make(string type, Dictionary<string, object>? fields = null)
    {
        var v = fields is null ? new Dictionary<string, object>() : new(fields);
        v["v"] = 1; v["id"] = Guid.NewGuid().ToString("D"); v["type"] = type;
        return ControlJson.Parse(JsonSerializer.SerializeToUtf8Bytes(v));
    }
}
public static class ControlJson
{
    private const string Uuid = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
    private const string Filename = @"(?!.*\.\.)(?!(?:[cC][oO][nN]|[pP][rR][nN]|[aA][uU][xX]|[nN][uU][lL]|[cC][oO][mM][1-9]|[lL][pP][tT][1-9])(?:\.|$))[A-Za-z0-9](?:[A-Za-z0-9._ -]{0,118}[A-Za-z0-9_-])?";
    private static bool Match(string text, string pattern) => Regex.IsMatch(text, @"\A(?:" + pattern + @")\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    public static int ScalarCount(string s)
    {
        int count = 0;
        for (int i = 0; i < s.Length; i++, count++)
        {
            if (char.IsHighSurrogate(s[i])) { if (++i >= s.Length || !char.IsLowSurrogate(s[i])) throw new InvalidDataException("surrogate"); }
            else if (char.IsLowSurrogate(s[i])) throw new InvalidDataException("surrogate");
        }
        return count;
    }
    public static ControlMessage Parse(byte[] data)
    {
        try { return ParseCore(data); }
        catch (Exception e) when (e is JsonException or DecoderFallbackException or InvalidOperationException or FormatException or KeyNotFoundException or OverflowException)
        { throw new InvalidDataException("invalid_json"); }
    }
    private static ControlMessage ParseCore(byte[] data)
    {
        if (data.Length is 0 or >65536) throw new InvalidDataException("size");
        _ = new UTF8Encoding(false, true).GetString(data);
        using var doc = JsonDocument.Parse(data, new JsonDocumentOptions { MaxDepth = 2, AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow });
        if (doc.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException("object");
        var fields = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var p in doc.RootElement.EnumerateObject())
        {
            if (!fields.TryAdd(p.Name, p.Value.Clone())) throw new InvalidDataException("duplicate");
            switch (p.Value.ValueKind)
            {
                case JsonValueKind.String: ScalarCount(p.Value.GetString()!); break;
                case JsonValueKind.Number:
                    if (!Match(p.Value.GetRawText(), "0|[1-9][0-9]*")) throw new InvalidDataException("integer_token");
                    _ = p.Value.GetInt32(); break;
                case JsonValueKind.True: case JsonValueKind.False: break;
                default: throw new InvalidDataException("flat");
            }
        }
        var m = new ControlMessage(fields);
        if (fields["v"].ValueKind != JsonValueKind.Number || m.Integer("v") != 1 || !Match(m.Id, Uuid)) throw new InvalidDataException("header");
        string[] extras;
        bool GoodId(string key) => Match(m.String(key), Uuid);
        bool Range(string key, int min, int max) => fields[key].ValueKind == JsonValueKind.Number && m.Integer(key) >= min && m.Integer(key) <= max;
        switch (m.Type)
        {
            case "hello": extras = ["deviceId","displayName"];
                if (!GoodId("deviceId") || ScalarCount(m.String("displayName")) is <1 or >64) throw new InvalidDataException("hello"); break;
            case "textOffer": extras = ["byteCount","scalarCount"];
                if (!Range("byteCount",1,32768) || !Range("scalarCount",1,8192)) throw new InvalidDataException("offer"); break;
            case "textData": extras = ["offerId","text"];
                if (!GoodId("offerId") || ScalarCount(m.String("text")) is <1 or >8192) throw new InvalidDataException("text"); break;
            case "fileOffer": extras = ["name","size","sha256"];
                if (!Match(m.String("name"),Filename) || !Range("size",0,1073741824) || !Match(m.String("sha256"),"[0-9a-f]{64}")) throw new InvalidDataException("file"); break;
            case "decision": case "fileDecision": extras = ["offerId","accept"];
                if (!GoodId("offerId")) throw new InvalidDataException("id"); _ = m.Boolean("accept"); break;
            case "receipt": case "cancel": case "fileEnd": case "fileReceipt": case "fileCancel": extras = ["offerId"];
                if (!GoodId("offerId")) throw new InvalidDataException("id"); break;
            case "error": extras = ["code"];
                if (!new[] {"unsupported","denied","invalid","timeout","integrity"}.Contains(m.String("code"))) throw new InvalidDataException("error"); break;
            default: throw new InvalidDataException("type");
        }
        if (!fields.Keys.ToHashSet().SetEquals(new[] {"v","type","id"}.Concat(extras))) throw new InvalidDataException("fields");
        return m;
    }
}
