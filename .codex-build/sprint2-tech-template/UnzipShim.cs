using System;
using System.IO;
using System.IO.Compression;

public static class UnzipShim
{
    public static int Main(string[] args)
    {
        if (args.Length < 2) return 2;
        using (var stream = File.OpenRead(args[1]))
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Read))
        {
            if (args[0] == "-Z1")
            {
                foreach (var entry in archive.Entries) Console.WriteLine(entry.FullName);
                return 0;
            }
            if (args[0] == "-p" && args.Length >= 3)
            {
                foreach (var entry in archive.Entries)
                {
                    if (entry.FullName == args[2])
                    {
                        using (var input = entry.Open())
                        using (var output = Console.OpenStandardOutput()) input.CopyTo(output);
                        return 0;
                    }
                }
                return 11;
            }
        }
        return 2;
    }
}
