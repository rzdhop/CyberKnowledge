using HarmonyLib;
using System;
using System.IO;
using System.Reflection;

// Initialisation du patch
// (Remplacer "com.example.patch.load" par "com.example.patch.loadmulti" si plusieurs patches)
var harmony = new Harmony("com.example.patch.load");
harmony.PatchAll(); // Applique les patches

// Chargement de la DLL patchée
Assembly assembly = Assembly.LoadFrom("C:\\Users\\ridap\\Downloads\\DLLception.dll");
Type type = assembly.GetType("btJuHzNucnTGdQAZwMmMnhZQZkH");
if (type == null)
    return;

MethodInfo method = type.GetMethod("RcyBinrittxjWupPNlCeddcAqv");
method?.Invoke(type, null);

Console.WriteLine("Done. Press any key to exit.");
Console.ReadKey();


// Patch sur Assembly.Load(byte[])
[HarmonyPatch(typeof(Assembly), "Load", new Type[] { typeof(byte[]) })]
public static class Patch_LoadRaw
{
    static void Prefix(byte[] rawAssembly)
    {
        DumpHelper.DumpBytes(rawAssembly);
    }
}

// Stocke un compteur pour nommer les dumps
public static class DumpCounter
{
    public static int Counter = 1;
}

// Effectue l'écriture disque des octets chargés
public static class DumpHelper
{
    public static void DumpBytes(byte[] data)
    {
        string dumpDir = @"C:\temp";
        Directory.CreateDirectory(dumpDir);

        string outPath = Path.Combine(dumpDir, $"DLLdump_{DumpCounter.Counter++}.dll");
        File.WriteAllBytes(outPath, data);

        Console.WriteLine($"[+] Dumped (Bytes) -> {outPath}");
    }
}