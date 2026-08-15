using System;
using System.IO;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using System.Numerics;

namespace Polyglot.CSharp.EntropyAnalyzer
{
    /// <summary>
    /// Configuration for entropy analysis parameters.
    /// </summary>
    public sealed class EntropyConfig
    {
        public const int DefaultChunkSize = 65536; // 64KB chunks
        public const int MinFileSize = 1024;       // Minimum file size to analyze
        
        public int ChunkSize { get; set; } = DefaultChunkSize;
        public int WindowSize { get; set; } = 4096; // Sliding window for peak detection
        public double PeakThreshold { get; set; } = 7.5; // Bits per byte threshold
        
        public bool StreamMode { get; set; } = true;
    }

    /// <summary>
    /// Represents a single chunk's entropy analysis result.
    /// </summary>
    public sealed class ChunkResult
    {
        public long Offset { get; set; }
        public int Size { get; set; }
        public double Entropy { get; set; }
        public byte[] Data { get; set; }
        
        public bool IsHighEntropy => Entropy > 7.0;
    }

    /// <summary>
    /// Represents a peak entropy region detected in the file.
    /// </summary>
    public sealed class PeakRegion
    {
        public long StartOffset { get; set; }
        public int Length { get; set; }
        public double AverageEntropy { get; set; }
        public string LikelyCause { get; set; } // "Packer", "Encryption", etc.
        
        public static readonly PeakRegion Empty = new PeakRegion 
        { 
            StartOffset = -1, 
            Length = 0, 
            AverageEntropy = 0,
            LikelyCause = null 
        };

        public override string ToString() => 
            $"[{StartOffset:X8}] +{Length} @ {AverageEntropy:F2} bits/byte ({LikelyCause})";
    }

    /// <summary>
    /// Main entropy analyzer class.
    /// </summary>
    public sealed class EntropyAnalyzer : IDisposable
    {
        private readonly EntropyConfig _config;
        private readonly byte[] _buffer;
        private readonly List<ChunkResult> _chunks;
        
        public double TotalEntropy => CalculateTotalEntropy();

        public PeakRegion? HighEntropyPeak { get; private set; }

        public EntropyAnalyzer(EntropyConfig config = null)
        {
            _config = config ?? new EntropyConfig();
            _buffer = new byte[_config.ChunkSize];
            _chunks = new List<ChunkResult>();
        }

        /// <summary>
        /// Analyzes a file path and returns complete results.
        /// </summary>
        public AnalysisResult AnalyzeFile(string filePath)
        {
            if (string.IsNullOrEmpty(filePath))
                throw new ArgumentException("Path cannot be null or empty", nameof(filePath));

            var fileInfo = new FileInfo(filePath);
            
            if (!fileInfo.Exists || fileInfo.Length < _config.MinFileSize)
                return CreateEmptyResult(fileInfo.Name, 0, "File not found or too small");

            using (var stream = File.OpenRead(filePath))
            {
                return AnalyzeStream(stream, fileInfo.Name, fileInfo.Length);
            }
        }

        /// <summary>
        /// Analyzes an existing stream.
        /// </summary>
        public AnalysisResult AnalyzeStream(Stream stream, string name, long length)
        {
            if (stream == null || length <= 0)
                return CreateEmptyResult(name, 0, "Invalid stream");

            var result = new AnalysisResult
            {
                Name = name,
                Path = "", // Set by caller if needed
                TotalSize = length,
                OverallEntropy = 0.0,
                Chunks = new List<ChunkResult>(),
                Peaks = new List<PeakRegion>
            };

            long offset = 0;
            
            while (offset < length)
            {
                int toRead = _config.ChunkSize > 0 
                    ? Math.Min(_config.ChunkSize, (int)(length - offset))
                    : (int)Math.Min(65536, length - offset);

                if (toRead <= 0) break;

                stream.Position = offset;
                int bytesRead = stream.Read(_buffer, 0, toRead);

                if (bytesRead == 0) break;

                var chunkResult = CalculateChunkEntropy(offset, _buffer, bytesRead);
                result.Chunks.Add(chunkResult);

                // Track peaks
                if (chunkResult.Entropy > result.OverallEntropy && 
                   chunkResult.Entropy >= _config.PeakThreshold)
                {
                    result.OverallEntropy = chunkResult.Entropy;
                    
                    var peak = new PeakRegion
                    {
                        StartOffset = offset,
                        Length = bytesRead,
                        AverageEntropy = chunkResult.Entropy,
                        LikelyCause = DetectLikelyCause(chunkResult)
                    };

                    // Merge overlapping peaks
                    if (result.Peaks.Count > 0 && 
                       result.Peaks.Last().StartOffset + result.Peaks.Last().Length >= offset)
                    {
                        var lastPeak = result.Peaks[result.Peaks.Count - 1];
                        lastPeak.Length += bytesRead;
                        lastPeak.AverageEntropy = CalculateWeightedAverage(
                            lastPeak.AverageEntropy, bytesRead, 
                            chunkResult.Entropy);
                    }
                    else
                    {
                        result.Peaks.Add(peak);
                    }

                    HighEntropyPeak = peak;
                }

                offset += bytesRead;
            }

            // Calculate overall entropy from all chunks
            if (result.Chunks.Count > 0)
            {
                var totalBytes = result.Chunks.Sum(c => c.Size);
                double sumWeighted = result.Chunks.Sum(
                    c => c.Entropy * c.Size / totalBytes);
                
                result.OverallEntropy = sumWeighted;
            }

            return result;
        }

        /// <summary>
        /// Calculates entropy for a single chunk of data.
        /// </summary>
        private ChunkResult CalculateChunkEntropy(long offset, byte[] buffer, int size)
        {
            var counts = new byte[256];
            
            // Count byte frequencies
            foreach (var b in buffer.Take(size))
                counts[b]++;

            // Calculate Shannon entropy
            double entropy = 0.0;
            for (int i = 0; i < 256; i++)
            {
                if (counts[i] > 0)
                {
                    double p = counts[i] / size;
                    entropy -= p * Math.Log(p, 2);
                }
            }

            return new ChunkResult
            {
                Offset = offset,
                Size = size,
                Entropy = entropy,
                Data = buffer.Take(size).ToArray()
            };
        }

        /// <summary>
        /// Calculates total entropy across entire file.
        /// </summary>
        private double CalculateTotalEntropy()
        {
            if (_chunks.Count == 0) return 0;

            var totalBytes = _chunks.Sum(c => c.Size);
            double sumWeighted = _chunks.Sum(
                c => c.Entropy * c.Size / totalBytes);

            return sumWeighted;
        }

        /// <summary>
        /// Detects likely cause of high entropy region.
        /// </summary>
        private string DetectLikelyCause(ChunkResult chunk)
        {
            // Heuristics based on common packer characteristics
            if (chunk.Offset % 4096 == 0 && chunk.Entropy > 7.2)
                return "Possible UPX/Pack";

            if (chunk.Offset % 8192 == 0 && chunk.Entropy > 7.3)
                return "Possible Themida/VMProtect";

            // Check for common encryption patterns
            var byteCount = chunk.Data.Count(b => b < 32);
            double lowByteRatio = (double)byteCount / chunk.Size;

            if (lowByteRatio > 0.85)
                return "Possible Encryption/Compression";

            return "Unknown - High Entropy Region";
        }

        /// <summary>
        /// Calculates weighted average of two entropy values.
        /// </summary>
        private double CalculateWeightedAverage(double avg1, int size1, double avg2)
        {
            if (size1 == 0 || avg2 <= 0) return avg1;
            return (avg1 * size1 + avg2 * _config.WindowSize) / (size1 + _config.WindowSize);
        }

        /// <summary>
        /// Creates an empty result with default values.
        /// </summary>
        private AnalysisResult CreateEmptyResult(string name, long size, string reason = "")
        {
            return new AnalysisResult
            {
                Name = name,
                TotalSize = size,
                OverallEntropy = 0.0,
                Reason = reason
            };
        }

        /// <summary>
        /// Serializes results to JSON format compatible with packpeek.
        /// </summary>
        public string ToJson(AnalysisResult result)
        {
            var sb = new StringBuilder();
            
            sb.Append('{');
            sb.Append($"\"name\":\"{result.Name}\",");
            sb.Append($"\"size\":{result.TotalSize},");
            sb.Append($"\"overall_entropy\":{result.OverallEntropy:F4}");

            if (!string.IsNullOrEmpty(result.Reason))
                sb.Append($$",\"reason\":\"{result.Reason}\"");

            // Add chunks summary
            var highEntropyCount = result.Chunks.Count(c => c.IsHighEntropy);
            sb.Append($",\"high_entropy_chunks\":{highEntropyCount}");

            // Add peaks
            if (result.Peaks.Count > 0)
            {
                sb.Append(",\"peaks\":[");
                for (int i = 0; i < result.Peaks.Count; i++)
                {
                    var p = result.Peaks[i];
                    sb.Append('{');
                    sb.Append($"\"offset\":{p.StartOffset},");
                    sb.Append($"\"length\":{p.Length},");
                    sb.Append($"\"entropy\":{p.AverageEntropy:F2}");
                    
                    if (!string.IsNullOrEmpty(p.LikelyCause))
                        sb.Append($$",\"cause\":\"{p.LikelyCause}\"");

                    sb.Append('}');
                    if (i < result.Peaks.Count - 1) sb.Append(',');
                }
                sb.Append(']');
            }

            // Add summary stats
            var avgEntropy = result.Chunks.Count > 0 
                ? result.OverallEntropy / result.Chunks.Count 
                : 0;
            
            sb.Append($",\"avg_entropy\":{avgEntropy:F4}");

            sb.Append('}');
            return sb.ToString();
        }

        /// <summary>
        /// Outputs SARIF-compatible format for CI integration.
        /// </summary>
        public string ToSarif(AnalysisResult result)
        {
            var runs = new List<Run>();

            foreach (var chunk in result.Chunks.Where(c => c.IsHighEntropy))
            {
                var locations = new List<Location[]>();
                
                // Create location for this high-entropy region
                var locs = new[]
                {
                    new Location
                    {
                        PhysicalLocation = new PhysicalLocation
                        {
                            ArtifactLocation = new ArtifactLocation
                            {
                                Uri = $"file://{chunk.Offset:X8}"
                            }
                        },
                        Region = new Region
                        {
                            StartLine = 1,
                            EndLine = 1,
                            StartColumn = 0,
                            EndColumn = chunk.Size
                        }
                    }
                };

                var runsItem = new Run
                {
                    Name = "High Entropy Detection",
                    Tool = new Tool
                    {
                        Driver = new ToolComponent
                        {
                            Name = "EntropyAnalyzer",
                            Version = "1.0.0"
                        }
                    },
                    Results = new List<Result>
                    {
                        new Result
                        {
                            Level = chunk.Entropy > 7.5 ? "error" : "warning",
                            Message = new Message
                            {
                                Text = $"High entropy region detected: {chunk.Entropy:F2} bits/byte"
                            },
                            Locations = locs,
                            RuleId = "HIGH_ENTROPY",
                            RuleName = "Possible Packer or Encryption"
                        }
                    }
                };

                runs.Add(runsItem);
            }

            var sarif = new SarifReport
            {
                SchemaVersion = "2.1.0",
                Runs = runs,
                Version = 1
            };

            return JsonSerializer.Serialize(sarif);
        }

        /// <summary>
        /// Clears internal buffers for memory management.
        /// </summary>
        public void Clear()
        {
            _chunks.Clear();
            HighEntropyPeak = null;
        }

        /// <summary>
        /// Disposes of managed resources.
        /// </summary>
        public void Dispose()
        {
            Clear();
            GC.SuppressFinalize(this);
        }

        ~EntropyAnalyzer() => Dispose();
    }

    // ============================================================================
    // SARIF Data Models (Simplified for compatibility)
    // ============================================================================

    public class SarifReport
    {
        public string SchemaVersion { get; set; } = "2.1.0";
        public int Version { get; set; }
        public List<Run> Runs { get; set; } = new List<Run>();
    }

    public class Run
    {
        public string Name { get; set; }
        public Tool Tool { get; set; }
        public List<Result> Results { get; set; } = new List<Result>();
    }

    public class Tool
    {
        public ToolComponent Driver { get; set; }
    }

    public class ToolComponent
    {
        public string Name { get; set; }
        public string Version { get; set; }
    }

    public class Result
    {
        public string Level { get; set; } = "warning";
        public Message Message { get; set; }
        public List<Location> Locations { get; set; } = new List<Location>();
        public string RuleId { get; set; }
        public string RuleName { get; set; }
    }

    public class Message
    {
        public string Text { get; set; }
    }

    public class Location
    {
        public PhysicalLocation PhysicalLocation { get; set; }
        public Region Region { get; set; }
    }

    public class PhysicalLocation
    {
        public ArtifactLocation ArtifactLocation { get; set; }
    }

    public class ArtifactLocation
    {
        public string Uri { get; set; }
    }

    public class Region
    {
        public int StartLine { get; set; }
        public int EndLine { get; set; }
        public int StartColumn { get; set; }
        public int EndColumn { get; set; }
    }

    // ============================================================================
    // Analysis Result Container
    // ============================================================================

    public sealed class AnalysisResult
    {
        public string Name { get; set; } = "";
        public string Path { get; set; } = "";
        public long TotalSize { get; set; }
        public double OverallEntropy { get; set; }
        
        /// <summary>High entropy chunk count (entropy > 7.0)</summary>
        public int HighEntropyChunkCount => 
            Chunks.Count(c => c.Entropy > 7.0);

        /// <summary>All chunks analyzed</summary>
        public List<ChunkResult> Chunks { get; set; } = new List<ChunkResult>();

        /// <summary>Detect peak regions</summary>
        public List<PeakRegion> Peaks { get; set; } = new List<PeakRegion>();

        /// <summary>Reason for low/high entropy classification</summary>
        public string Reason { get; set; } = "";

        /// <summary>Classification: Normal, Suspicious, LikelyPacked</summary>
        public ClassificationLevel Classification => 
            Classify(OverallEntropy);

        public override string ToString()
        {
            return $"[{Name}] Size={TotalSize} bytes, " +
                   $"Entropy={OverallEntropy:F2}, " +
                   $"Classification={Classification}";
        }
    }

    ///