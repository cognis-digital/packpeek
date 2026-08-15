#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'digest/sha1'

module Packpeek
  # Thresholds for common packers (bits per byte)
  PACKER_THRESHOLDS = {
    upx:        { min: 6.5, max: 7.2 },
    aspack:     { min: 6.8, max: 7.4 },
    themida:    { min: 6.9, max: 7.3 },
    mpress:     { min: 6.6, max: 7.1 },
    vmprotect:  { min: 6.7, max: 7.2 },
    generic:    { min: 6.5, max: 7.4 }
  }.freeze

  # Minimum file size for meaningful entropy calculation (bytes)
  MIN_FILE_SIZE = 1024

  # Maximum chunk size for streaming large files
  CHUNK_SIZE = 8 * 1024

  class EntropyAnalyzer
    attr_reader :filename, :size, :entropy, :chunked, :packer_hint

    def initialize(filename)
      @filename = filename
      @size = 0
      @entropy = 0.0
      @chunked = false
      @packer_hint = nil
    end

    # Calculate Shannon entropy of a file
    # Returns hash with metadata and analysis results
    def analyze(stream: true, chunk_size: CHUNK_SIZE)
      return {} unless File.exist?(@filename)

      @size = File.size(@filename)

      if @size < MIN_FILE_SIZE
        @entropy = 0.0
        @chunked = false
        @packer_hint = 'too_small'
        return metadata.merge(analysis: { status: :too_small, entropy: 0.0 })
      end

      # Use streaming for large files to avoid memory spikes
      if stream && @size > 10 * 1024 * 1024
        @chunked = true
        analyze_stream(chunk_size)
      else
        analyze_full
      end

      metadata.merge(analysis: { status: :ok, entropy: @entropy })
    end

    private

    def analyze_full
      data = File.binread(@filename)
      calculate_entropy(data)
    end

    def analyze_stream(chunk_size)
      byte_counts = Hash.new(0)
      total_bytes = 0

      File.open(@filename, 'rb') do |f|
        while chunk = f.read(chunk_size)
          next if chunk.empty?
          
          chunk.each_byte do |b|
            byte_counts[b] += 1
            total_bytes += 1
          end
        end
      end

      calculate_entropy(byte_counts, total_bytes)
    end

    def calculate_entropy(byte_counts, total = nil)
      return 0.0 if total.nil? || total == 0

      total = byte_counts.values.sum rescue total
      
      # Shannon entropy: -sum(p * log2(p)) for each unique byte
      @entropy = 0.0
      byte_counts.each do |_, count|
        p = count.to_f / total
        @entropy -= (p * Math.log2(p) if p > 0)
      end

      # Normalize to bits per byte (max is 8.0 for 256 unique bytes)
      @entropy = (@entropy / 8.0).round(4)
    end

    def metadata
      {
        filename: @filename,
        size: @size,
        chunked: @chunked,
        timestamp: Time.now.to_f,
        packer_thresholds: PACKER_THRESHOLDS.dup
      }
    end

    def analysis
      result = { status: :ok, entropy: @entropy }

      # Check against packer thresholds
      if !@packer_hint && @size >= MIN_FILE_SIZE
        detected = detect_packer
        result[:packer] = detected unless detected.nil?
      end

      result
    end

    def detect_packer
      return nil if @entropy < 6.0 || @entropy > 7.5

      PACKER_THRESHOLDS.each do |name, range|
        next if name == :generic
        
        if @entropy >= range[:min] && @entropy <= range[:max]
          # Additional heuristic: packers often produce very uniform entropy
          return name
        end
      end

      nil
    rescue StandardError
      nil
    end
  end
end

# =============================================================================
# CLI Interface & Demo
# =============================================================================

def run_cli(args = ARGV)
  analyzer = Packpeek::EntropyAnalyzer.new(args.first || '-')

  result = analyzer.analyze(stream: true, chunk_size: Packpeek::EntrophyAnalyzer::CHUNK_SIZE)

  puts JSON.pretty_generate(result)
end

if __FILE__ == $0
  # Demo with built-in test files
  demo_files = [
    'polyglot/ruby/entropy_analyzer.rb',
    '/etc/passwd' if File.exist?('/etc/passwd'),
    '/bin/bash' if File.exist?('/bin/bash')
  ].compact

  puts "Packpeek Entropy Analyzer Demo"
  puts "=" * 40
  puts

  demo_files.each do |path|
    next unless File.exist?(path)
    
    analyzer = Packpeek::EntropyAnalyzer.new(path)
    result = analyzer.analyze(stream: true, chunk_size: Packpeek::EntrophyAnalyzer::CHUNK_SIZE)
    
    puts "File: #{path}"
    puts "  Size:   #{result[:metadata][:size]} bytes"
    puts "  Entropy: #{result[:analysis][:entropy].round(4)} bits/byte"
    puts "  Status:  #{result[:analysis][:status]}"
    
    if result[:analysis][:packer]
      puts "  Packer:  #{result[:analysis][:packer]}"
    end
    
    puts
  end

  # Interactive mode
  print "\nEnter filename (or '-' for stdin, or Ctrl-D to quit): "
  input = gets.chomp
  
  if input == '-' || input.empty?
    run_cli('-')
  else
    run_cli([input])
  end
end