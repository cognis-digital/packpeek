using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Diagnostics;

namespace PackPeek.Core.Parsers
{
    /// <summary>
    /// Complete binary parser for detecting packers (UPX, ASPack, Themida, MPRESS, VMProtect)
    /// and calculating section entropy. Emits YARA and SARIF output formats.
    /// </summary>
    public class BinaryParser
    {
        private readonly byte[] _data;
        private readonly string _filename;

        // Known magic signatures for packers (offset 0x40 is common for UPX)
        private static readonly Dictionary<string, Func<byte[], int>> PackerSignatures = new()
        {
            ["UPX"] = (data) => FindSignature(data, "UPX!"),
            ["ASPack"] = (data) => FindString(data, "ASPack"),
            ["Themida"] = (data) => FindString(data, "Themida") || FindString(data, "THEMIDA"),
            ["MPRESS"] = (data) => FindSignature(data, 0x4D505245), // "MPRE"
            ["VMProtect"] = (data) => FindSignature(data, 0x564D5052), // "VMPR"
        };

        public BinaryParser(byte[] data, string filename = null)
        {
            _data = data;
            _filename = filename ?? Path.GetFileName("unknown");
        }

        /// <summary>
        /// Main entry point for parsing a binary file.
        /// </summary>
        public ParsedResult Parse()
        {
            var result = new ParsedResult(_filename);

            // 1. Basic header analysis
            AnalyzeHeader(result);

            // 2. Section entropy calculation
            CalculateSectionEntropy(result);

            // 3. Packer detection
            DetectPackers(result);

            // 4. String extraction for additional clues
            ExtractSuspiciousStrings(result);

            return result;
        }

        private void AnalyzeHeader(ParsedResult result)
        {
            if (_data.Length == 0)
                return;

            // Check file size anomalies (packed files often have specific sizes)
            var fileSize = _data.Length;
            result.FileSize = fileSize;

            // Calculate overall entropy as a quick indicator
            result.OverallEntropy = CalculateShannonEntropy(_data);
        }

        private void CalculateSectionEntropy(ParsedResult result)
        {
            if (_data.Length == 0)
                return;

            // Parse PE headers to get sections (simplified for demo - assumes valid PE)
            var peHeaderOffset = 64; // Standard PE header offset after DOS header
            if (peHeaderOffset >= _data.Length || !_IsPE(_data))
                return;

            // Read PE signature
            string peSig = Encoding.ASCII.GetString(_data, peHeaderOffset, 4);
            if (!peSig.Equals("PE\x00\x00", StringComparison.Ordinal))
                return;

            // Parse Optional Header to get section table
            int optionalHeaderStart = peHeaderOffset + 24; // After PE signature and fields
            ushort machineType = BitConverter.ToUInt16(_data, optionalHeaderStart);
            
            // Skip to Section Table RVA (offset 0x38 in optional header)
            int sectionTableRVA = BitConverter.ToInt32(_data, optionalHeaderStart + 0x38);
            
            if (sectionTableRVA == 0 || sectionTableRVA >= _data.Length)
                return;

            // Calculate file offset for section table: PE header + fields before sections
            int sectionTableOffset = peHeaderOffset + 64 + BitConverter.ToInt16(_data, optionalHeaderStart + 0x3C);
            
            if (sectionTableOffset >= _data.Length)
                return;

            // Read section count and names
            ushort sectionCount = BitConverter.ToUInt16(_data, sectionTableOffset);
            var sections = new List<SectionInfo>();

            for (int i = 0; i < sectionCount && i * 40 < _data.Length; i++)
            {
                int offset = sectionTableOffset + (i * 40);
                string name = Encoding.ASCII.GetString(_data, offset, 8).TrimEnd('\0');
                uint virtualSize = BitConverter.ToUInt32(_data, offset + 16);
                uint rawSize = BitConverter.ToUInt32(_data, offset + 20);

                sections.Add(new SectionInfo
                {
                    Name = name,
                    VirtualAddress = BitConverter.ToInt32(_data, optionalHeaderStart + 124), // Simplified
                    Size = (int)rawSize,
                });
            }

            foreach (var section in sections)
            {
                if (section.Size > 0 && section.Size < _data.Length)
                {
                    var offset = section.VirtualAddress;
                    var slice = new byte[section.Size];

                    // Handle virtual address vs file offset
                    if (offset >= _data.Length)
                        continue;

                    int end = Math.Min(offset + section.Size, _data.Length);
                    Array.Copy(_data, offset, slice, 0, end - offset);

                    var entropy = CalculateShannonEntropy(slice);
                    result.Sections.Add(new SectionEntropyResult
                    {
                        Name = section.Name,
                        VirtualSize = section.Size,
                        Entropy = entropy,
                        HighEntropyThreshold = 7.5, // Typical for packed sections
                    });
                }
            }
        }

        private void DetectPackers(ParsedResult result)
        {
            var findings = new List<PackerFinding>();

            foreach (var kvp in PackerSignatures)
            {
                try
                {
                    int offset = kvp.Value(_data);
                    if (offset >= 0 && offset < _data.Length)
                    {
                        findings.Add(new PackerFinding
                        {
                            Name = kvp.Key,
                            Type = "MagicHeader",
                            Offset = offset,
                            Confidence = 0.95m,
                        });
                    }
                }
                catch (Exception ex)
                {
                    // Silently handle parse errors
                }
            }

            result.Packers = findings;
        }

        private void ExtractSuspiciousStrings(ParsedResult result)
        {
            var suspiciousPatterns = new[]
            {
                "UPX", "ASPack", "Themida", "MPRESS", "VMProtect",
                ".text", ".rdata", ".idata", ".reloc",
                "DllMain", "WinMain", "CRT"
            };

            foreach (var pattern in suspiciousPatterns)
            {
                try
                {
                    int offset = FindString(_data, pattern);
                    if (offset >= 0)
                    {
                        result.Strings.Add(new StringFinding
                        {
                            Pattern = pattern,
                            Offset = offset,
                            Type = "Suspicious",
                        });
                    }
                }
                catch
                {
                    // Ignore errors
                }
            }
        }

        private static int CalculateShannonEntropy(byte[] data)
        {
            if (data == null || data.Length == 0)
                return 0;

            var counts = new byte[256];
            foreach (var b in data)
                counts[b]++;

            double entropy = 0.0;
            int total = data.Length;

            for (int i = 0; i < 256; i++)
            {
                if (counts[i] > 0)
                {
                    double p = (double)counts[i] / total;
                    entropy -= p * Math.Log(p, 2);
                }
            }

            return (int)(entropy * 100.0); // Return as integer percentage for easier comparison
        }

        private static int FindSignature(byte[] data, string signature)
        {
            var sigBytes = Encoding.ASCII.GetBytes(signature);
            if (sigBytes.Length > data.Length)
                return -1;

            for (int i = 0; i <= data.Length - sigBytes.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < sigBytes.Length; j++)
                {
                    if (data[i + j] != sigBytes[j])
                    {
                        match = false;
                        break;
                    }
                }

                if (match)
                    return i;
            }

            return -1;
        }

        private static int FindString(byte[] data, string pattern)
        {
            var sigBytes = Encoding.ASCII.GetBytes(pattern);
            if (sigBytes.Length > data.Length)
                return -1;

            for (int i = 0; i <= data.Length - sigBytes.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < sigBytes.Length; j++)
                {
                    if (data[i + j] != sigBytes[j])
                    {
                        match = false;
                        break;
                    }
                }

                if (match)
                    return i;
            }

            return -1;
        }

        private static bool _IsPE(byte[] data)
        {
            if (data.Length < 64)
                return false;

            string peSig = Encoding.ASCII.GetString(data, 64, 4);
            return peSig.Equals("PE\x00\x00", StringComparison.Ordinal);
        }

        /// <summary>
        /// Generates YARA rules from parser findings.
        /// </summary>
        public static string GenerateYaraRules(ParsedResult result)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// Auto-generated YARA rules for: " + result.FileName);
            sb.AppendLine("#pragma once");
            sb.AppendLine("");

            // UPX rule
            if (result.Packers.Any(p => p.Name == "UPX"))
            {
                sb.AppendLine("rule upx_detected");
                sb.AppendLine("{");
                sb.AppendLine("\tmeta:");
                sb.AppendLine("\t\tdescription = \"UPX packer detected\";");
                sb.AppendLine("\t\tauthor = \"PackPeek\";");
                sb.AppendLine("\t\tdate = \"" + DateTime.Now.ToString("yyyy-MM-dd") + "\";");
                sb.AppendLine("\t\ttags = {upx