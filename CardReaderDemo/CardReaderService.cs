using System.Text;
using PCSC;
using PCSC.Iso7816;
using PCSC.Monitoring;

namespace FillingKiosk.Client.Services;

public class CardReaderService
{
    private ISCardMonitor? _monitor;
    private readonly IContextFactory _contextFactory = ContextFactory.Instance;
    
    public Action<string>? OnCardInserted { get; set; }
    public Action<string>? OnCardRemoved { get; set; }

    public void StartMonitoring(Action<string>? onCardInserted = null, Action<string>? onCardRemoved = null)
    {
        var monitorFactory = MonitorFactory.Instance;
        _monitor = monitorFactory.Create(SCardScope.System);

        _monitor.CardInserted += (_, args) =>
        {
            Console.WriteLine($"Card inserted: {args.ReaderName}");
            onCardInserted?.Invoke(args.ReaderName);
            OnCardInserted?.Invoke(args.ReaderName);
        };

        _monitor.CardRemoved += (_, args) =>
        {
            Console.WriteLine($"Card removed: {args.ReaderName}");
            onCardRemoved?.Invoke(args.ReaderName);
            OnCardRemoved?.Invoke(args.ReaderName);
        };

        var context = _contextFactory.Establish(SCardScope.System);
        var readers = context.GetReaders();
        if (readers.Length == 0)
        {
            Console.WriteLine("No smart card readers found.");
            return;
        }

        _monitor.Start(readers);
    }

    public void StopMonitoring()
    {
        _monitor?.Cancel();
    }

    public string? GetCardPanInfo()
    {
        try
        {
            using var context = _contextFactory.Establish(SCardScope.System);
            var readers = context.GetReaders();

            if (readers.Length == 0)
                return "No smart card readers found.";

            var readerName = readers[0];
            using var isoReader = new IsoReader(context, readerName, SCardShareMode.Shared, SCardProtocol.Any, false);

            // SELECT PSE
            var pseSelect = new CommandApdu(IsoCase.Case3Short, isoReader.ActiveProtocol)
            {
                CLA = 0x00, INS = 0xA4, P1 = 0x04, P2 = 0x00,
                Data = Encoding.ASCII.GetBytes("1PAY.SYS.DDF01")
            };
            var pseResp = isoReader.Transmit(pseSelect);
            var pseData = GetFullResponse(isoReader, pseResp);

            var aid = ParseTlv(pseData, 0x4F);
            if (aid == null) return "No AID found in PSE response.";

            // SELECT AID
            var aidSelect = new CommandApdu(IsoCase.Case3Short, isoReader.ActiveProtocol)
            {
                CLA = 0x00, INS = 0xA4, P1 = 0x04, P2 = 0x00,
                Data = aid
            };
            var aidResp = isoReader.Transmit(aidSelect);
            var aidData = GetFullResponse(isoReader, aidResp);

            // READ RECORDs
            for (int sfi = 1; sfi <= 10; sfi++)
            {
                for (int rec = 1; rec <= 10; rec++)
                {
                    var readRecord = new CommandApdu(IsoCase.Case2Short, isoReader.ActiveProtocol)
                    {
                        CLA = 0x00, INS = 0xB2,
                        P1 = (byte)rec,
                        P2 = (byte)((sfi << 3) | 4),
                        Le = 0x00
                    };

                    var resp = isoReader.Transmit(readRecord);
                    if (resp.SW1 == 0x6C)
                    {
                        readRecord.Le = resp.SW2;
                        resp = isoReader.Transmit(readRecord);
                    }

                    if (resp.SW1 != 0x90) continue;

                    var recordData = resp.GetData();
                    var track2 = ParseTlv(recordData, 0x57);
                    if (track2 == null) continue;

                    var track2Str = BitConverter.ToString(track2).Replace("-", "");
                    if (!track2Str.Contains("D")) continue;

                    var pan = track2Str.Split('D')[0];
                    var yyMM = track2Str.Split('D')[1].Substring(0, 4);
                    var expiry = $"20{yyMM[..2]}/{yyMM[2..]}";

                    return $"PAN: {pan}, Expiry: {expiry}";
                }
            }

            return "Track 2 (PAN) not found in any record.";
        }
        catch (Exception ex)
        {
            return $"Error: {ex.Message}";
        }
    }

    private static byte[] GetFullResponse(IsoReader reader, Response initial)
    {
        var data = initial.GetData() ?? [];
        while (initial.SW1 == 0x61)
        {
            var getResponse = new CommandApdu(IsoCase.Case2Short, reader.ActiveProtocol)
            {
                CLA = 0x00, INS = 0xC0, P1 = 0x00, P2 = 0x00, Le = initial.SW2
            };
            initial = reader.Transmit(getResponse);
            data = data.Concat(initial.GetData() ?? []).ToArray();
        }
        return data;
    }

    private static byte[]? ParseTlv(byte[] data, byte tag)
    {
        int i = 0;
        while (i < data.Length - 1)
        {
            var currentTag = data[i++];
            var length = data[i++];

            if (currentTag == tag && i + length <= data.Length)
                return data.Skip(i).Take(length).ToArray();

            i += length;
        }
        return null;
    }
}
