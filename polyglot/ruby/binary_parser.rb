require 'json'
require 'digest/sha1'
require 'zlib'

module Packpeek
  VERSION = "0.1.0"

  # Magic bytes for known packers
  PACKER_SIGNATURES = {
    :upx => "\x4D\x50",           # UPX!
    :aspack => "\x53\x48\x49\x46\x4C\x4F\x57", # "ASPack"
    :themida => ["\x54\x68\x65\x6D\x69\x64\x61", "\x54\x68\x6D\x69\x64\x61"], # "Themida"/"Thmida"
    :mpress => "\x4D\x50\x52\x45\x53\x53", # MPRESS
    :vmprotect => ["\x56\x4D\x50\x72\x6F\x74\x65\x63\x74", "\x56\x4D\x50\x72"]
  }.freeze

  class BinaryParser
    attr_reader :file_path, :data, :headers, :entropy

    def initialize(file_path = nil)
      @file_path = file_path
      @data = nil
      @headers = {}
      @entropy = 0.0
    end

    # Load binary data from file or stdin
    def load!
      return self.data if @data

      if @file_path
        File.open(@file_path, "rb") do |f|
          @data = f.read
        end
      else
        @data = STDIN.read
      end

      unless @data.is_a?(String) && !@data.empty?
        raise ArgumentError, "Empty or invalid binary data"
      end

      self
    end

    # Parse PE headers if present
    def parse_pe_headers!
      return self.headers if @headers.any? { |_, v| v[:found] }

      offset = 0
      while offset < @data.length - 64
        header = @data[offset, 64].bytes.to_a
        break unless header.all? { |b| b >= 0 && b <= 255 }

        # Check for PE signature "MZ" at current offset
        if header[0] == 80 && header[1] == 90 # 'M' = 76, 'Z' = 90 (ASCII)
          break
        end

        offset += 32
      end

      @headers[:pe_offset] = offset - 64 if offset > 0
      parse_pe_at(offset) unless offset == 0
    end

    # Parse PE header at given offset
    def parse_pe_at(pe_offset)
      return self.headers if pe_offset >= @data.length

      data = @data[pe_offset, 256]
      bytes = data.bytes.to_a

      # DOS header check
      dos_magic = [bytes[0], bytes[1]]
      
      unless dos_magic == [79, 80] # "MZ"
        @headers[:dos_found] = false
        return self.headers
      end

      # Extract PE header info from DOS stub
      pe_offset_val = (bytes[62] << 8) + bytes[63]
      
      if pe_offset_val > 0 && pe_offset_val < @data.length
        pe_data = @data[pe_offset_val, 256]
        pe_bytes = pe_data.bytes.to_a

        # PE signature "PE\0\0"
        unless [pe_bytes[0], pe_bytes[1]] == [80, 69]
          @headers[:dos_found] = false
          return self.headers
        end

        # Machine type (Intel x86 = 0x14c, x64 = 0x8664)
        machine_type = (pe_bytes[2] << 8) + pe_bytes[3]
        
        @headers[:dos_found] = true
        @headers[:machine_type] = {
          0x14c => "Intel x86",
          0x8664 => "Intel x64"
        }[machine_type] || machine_type.to_s

        # PE header fields
        @headers[:pe_offset] = pe_offset_val
        @headers[:timestamp] = (pe_bytes[18] << 24) | (pe_bytes[19] << 16) | 
                               (pe_bytes[20] << 8) | pe_bytes[21]
        
        # Optional header size
        opt_header_size = (pe_bytes[30] << 8) + pe_bytes[31]

        if opt_header_size > 0 && pe_offset_val + 56 < @data.length
          opt_data = @data[pe_offset_val + 56, opt_header_size]
          opt_bytes = opt_data.bytes.to_a

          # Optional header magic (PE32+ vs PE32)
          opt_magic = [opt_bytes[0], opt_bytes[1]]
          
          if opt_magic == [245, 22] # PE32+
            @headers[:pe_type] = "PE32+"
            subheader_offset = 96
          else
            @headers[:pe_type] = "PE32"
            subheader_offset = 80
          end

          if pe_offset_val + subheader_offset < @data.length
            sub_data = @data[pe_offset_val + subheader_offset, 128]
            sub_bytes = sub_data.bytes.to_a

            # Sub-header fields (ImageBase, SectionAlignment, etc.)
            @headers[:image_base] = (sub_bytes[4] << 32) | 
                                   (sub_bytes[5] << 24) | 
                                   (sub_bytes[6] << 16) | 
                                   (sub_bytes[7] << 8) | sub_bytes[8]
            
            @headers[:section_alignment] = (sub_bytes[10] << 8) + sub_bytes[11]
            @headers[:file_alignment] = (sub_bytes[12] << 8) + sub_bytes[13]

            # Number of sections
            num_sections = (sub_bytes[16] << 8) + sub_bytes[17]
            
            if num_sections > 0 && pe_offset_val + subheader_offset + 4 < @data.length
              section_data = @data[pe_offset_val + subheader_offset + 4, 
                                   num_sections * 40]
              
              sections = []
              i = 0
              while i < num_sections && i < section_data.length / 40
                sec_bytes = section_data[i*40, 40].bytes.to_a
                
                # Section name (8 bytes)
                name = [sec_bytes[0], sec_bytes[1]].pack("C2").upcase
                sections << {
                  :name => name,
                  :virtual_size => (sec_bytes[16] << 24) | 
                                  (sec_bytes[17] << 16) | 
                                  (sec_bytes[18] << 8) | sec_bytes[19],
                  :raw_size => (sec_bytes[20] << 24) | 
                             (sec_bytes[21] << 16) | 
                             (sec_bytes[22] << 8) | sec_bytes[23],
                  :virtual_address => (sec_bytes[24] << 24) | 
                                    (sec_bytes[25] << 16) | 
                                    (sec_bytes[26] << 8) | sec_bytes[27],
                  :raw_offset => (sec_bytes[32] << 24) | 
                               (sec_bytes[33] << 16) | 
                               (sec_bytes[34] << 8) | sec_bytes[35]
                }

                i += 1
              end

              @headers[:sections] = sections
            end
          end
        end
      end

      self.headers
    end

    # Detect packer signatures
    def detect_packer!
      return self.headers if @headers.key?(:packers)

      data = @data.dup
      
      # UPX detection (check multiple offsets)
      upx_found = []
      [0, 64].each do |offset|
        next unless offset + 2 < data.length
        magic = [data[offset], data[offset+1]]
        if magic == [76, 80] # "UP"
          upx_found << { :offset => offset, :type => :upx }
        end
      end

      # ASPack detection
      aspack_found = []
      [0, 64].each do |offset|
        next unless offset + 7 < data.length
        magic = [data[offset], data[offset+1], data[offset+2], 
                data[offset+3], data[offset+4], data[offset+5], 
                data[offset+6]]
        if magic == [83, 72, 73, 70, 76, 79, 87] # "ASPack"
          aspack_found << { :offset => offset, :type => :aspack }
        end
      end

      # Themida detection
      themida_found = []
      [0, 64].each do |offset|
        next unless offset + 7 < data.length
        magic1 = [data[offset], data[offset+1], data[offset+2], 
                 data[offset+3], data[offset+4], data[offset+5], 
                 data[offset+6]]
        magic2 = [data[offset], data[offset+1], data[offset+2], 
                 data[offset+3], data[offset+4], data[offset+5], 
                 data[offset+6] - 1] # Check for "Thmida" variant
        
        if magic1 == [84, 72, 101, 109, 105, 100, 97] ||
           magic2 == [84, 72, 101, 109, 105, 100, 97]
          themida_found << { :offset => offset, :type => :themida }
        end
      end

      # MPRESS detection
      mpress_found = []
      [0, 64].each do |offset|
        next unless offset + 6 < data.length
        magic = [data[offset], data[offset+1], data[offset+2], 
                data[offset+3], data[offset+4], data[offset+5]]
        if magic == [76, 80, 82, 69, 83, 83] # "MPRESS"
          mpress_found << { :offset => offset, :type => :mpress }
        end
      end

      # VMProtect detection
      vmprotect_found = []
      [0, 64].each do |offset|
        next unless offset + 8 < data.length
        magic1 = [data[offset], data[offset+1], data[offset+2], 
                 data[offset+3], data[offset+4], data[offset+5], 
                 data[offset+6], data[offset+7]]
        magic2 = [data[offset], data[offset+1], data[offset+2], 
                 data[offset+3], data[offset+4], data[offset+5], 82, 80] # "VMPro"
        
        if magic1 == [86, 77, 80, 114, 111, 116, 101, 99] ||
           magic2 == [86, 77, 80, 114, 111, 116, 82, 116]
          vmprotect_found << { :offset => offset, :type => :vmprotect }
        end
      end

      @headers[:packers] = {
        upx: upx_found.any?,
        aspack: aspack_found.any?,
        themida: themida_found.any?,
        mpress: mpress_found.any?,
        vmprotect: vmprotect_found.any?
      }

      self.headers
    end

    # Calculate Shannon entropy for data
    def calculate_entropy!
      return @entropy if @entropy > 0
      
      data = @data.dup
      length = data.length
      
      unless length > 0
        @entropy = 0.0
        return self.entropy
      end

      # Count byte frequencies
      freq = Hash.new(0)
      data.each_byte do |b|
        freq[b] += 1
      end

      # Calculate entropy
      total = length.to_f
      entropy = 0.0
      
      freq.each do |_, count|
        p = count / total
        entropy -= (p * Math.log2(p)) if p > 0 && !p.nan?
      end

      @entropy = entropy.round(4)
      
      # Also calculate per-section entropy if PE headers found
      if @headers[:dos_found]
        sections_entropy = []
        
        @headers[:sections].each do |section|
          next unless section[:raw_offset] > 0 && 
                      section[:raw_offset] + section[:raw_size] <= length

          sec_data = data[section[:raw_offset], section[:raw_size]]
          
          if sec_data.length > 16
            # Calculate entropy for this section
            sec_freq = Hash.new(0)
            sec_data.each_byte do |b|
              sec_freq[b] += 1
            end

            sec_total = sec_data.length.to_f
            sec_entropy = 0.0
            
            sec_freq.each do |_, count|
              sp = count / sec_total
              sec_entropy -= (sp * Math.log2(sp)) if sp > 0 && !sp.nan?
            end

            sections_entropy << {
              :name => section[:name],
              :entropy => sec_entropy.round(4)
            }
          end

          self.entropy = sections_entropy
        end
      end

      self.entropy
    end

    # Generate YARA rules output
    def generate_yara!
      return "" if @headers.key?(:yara_output)

      data = @data.dup
      length = data.length
      
      yara_rules = []
      
      # UPX rule
      if @headers[:packers][:upx]
        upx_offsets = []
        [0, 64].each do |offset|
          next unless offset + 2 < length
          if [data[offset], data[offset+1]] == [76, 80] # "UP"
            upx_offsets << { :offset => offset }
          end
        end
        
        yara_rules << "rule UPX_Detector {"
        yara_rules << "    meta:"
        yara_rules << "        description = \"UPX packer detected\""
        yara_rules << "        author = \"Packpeek\""
        yara_rules << "        date = \"#{Time.now.strftime('%Y-%m-%d')}\""
        yara_rules << "        version = \"1.0\""
        yara_rules << "    condition:"
        
        if upx_offsets.any?
          offsets_str = upx_offsets.map { |o| o[:offset].to_s }.join(", ")
          yara_rules << "        (std::string(data, 0, 2) == \"UPX!\")"
          yara_rules << "        || (std::string(data, #{upx_offsets.first[:offset]}, 2) == \"UPX!\")"
        else
          yara_rules << "        std::string(data, 0, 2) == \"UPX!\""
        end
        
        yara_rules << "}"

        self.yara_output = yara_rules.join("\n") + "\n\n"
      end

      # ASPack rule
      if @headers[:packers][:aspack]
        aspack_offsets = []
        [0, 64].each do |offset|
          next unless offset + 7 < length
          if [data[offset], data[offset+1], data[offset+2], 
              data[offset+3], data[offset+4], data[offset+5], 
              data[offset+6]] == [83, 72, 73, 70, 76, 79, 87] # "ASPack"
            aspack_offsets