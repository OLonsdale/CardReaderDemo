using CardReaderDemo;

using var reader = new CardReaderService();

reader.OnCardInserted += CardInserted;
reader.OnCardRemoved += CardRemoved;

reader.StartMonitoring();

Console.WriteLine("Insert a card. Press Enter to quit.");
Console.ReadLine();

void CardInserted(string readerName)
{
    Console.WriteLine();
    Console.WriteLine($"Inserted: {readerName}");

    var card = reader.GetCardInfo(readerName);

    if (!string.IsNullOrWhiteSpace(card.Error))
    {
        Console.WriteLine($"Error: {card.Error}");
        return;
    }

    Write("Reader", card.ReaderName);
    Write("Type", card.CardType);
    Write("AID", card.Aid);
    Write("Label", card.ApplicationLabel);
    Write("PAN", card.Pan);
    Write("Expiry", card.Expiry);
    Write("Name", card.CardholderName);
    Write("ATR", card.Atr);
}

void CardRemoved(string readerName)
{
    Console.WriteLine();
    Console.WriteLine($"Removed: {readerName}");
}

static void Write(string label, string? value)
{
    if (!string.IsNullOrWhiteSpace(value))
        Console.WriteLine($"{label,-10}: {value}");
}