import re

class Log2matrix:
    """
    A class to parse log files, extract hexadecimal blocks, and convert them into matrices.
    """
    def __init__(self,file_path:str = r"D:\VScode\project\event_log\example\smbios.log"):
        """
        Initialize the Log2matrix instance.

        :param file_path: Path to the log file to process.
        """
        self.file_path = file_path
    def extract_hex_blocks(self)->list:
        """
        Extract hexadecimal blocks from the log file.

        :return: A list of strings, each representing a block of hexadecimal lines.
        """
        hex_blocks = []
        current_block = []
        block_count = 0 

        
        hex_line_pattern = re.compile(
            r"^[0-9A-Fa-f]{8}:"
        )

        # Keyword to detect the end of processing.
        terminate_keyword = "SMBIOS 3.0 (64-bit) Entry Point Structure:"        
        with open(self.file_path, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()

                # Stop processing if the terminate keyword is found.
                if terminate_keyword in line:
                    if current_block:
                        block_count += 1
                        hex_blocks.append(f"Block {block_count}:\n" + "\n".join(current_block))
                    break

                
                if hex_line_pattern.match(line):
                    current_block.append(line)
                else:
                    # If a non-hexadecimal line is encountered, finalize the current block.
                    if current_block:
                        block_count += 1
                        hex_blocks.append(f"Block {block_count}:\n" + "\n".join(current_block))
                        current_block = []

            # Ensure the last block is saved.
            if current_block:
                block_count += 1
                hex_blocks.append(f"Block {block_count}:\n" + "\n".join(current_block))

        return hex_blocks


    def mk_hex_matrix(self,data:list)->list:
        """
        Convert extracted hexadecimal data into matrices.

        :param data: A list of hexadecimal blocks to process.
        :return: A list of tuples containing block labels and their corresponding matrices.
        """
        self.data = data
    
        block_pattern = re.compile(r"^(Block \d+:)|(?<=: )(.*?)(?= \*)")

        results = []
        current_matrix = []
        current_block = None

        for line in self.data.splitlines():
            match = block_pattern.search(line)
            if match:
                if match.group(1): 
                    if current_matrix:  
                        results.append((current_block, current_matrix))
                        current_matrix = []
                    current_block = match.group(1) 
                elif match.group(2):  
                    hex_line = match.group(2).replace("-", " ").split()  
                    current_matrix.append(hex_line)

        
        if current_matrix:
            results.append((current_block, current_matrix))

        return results
    def log2matrix(self):
        """
        Extract and process log data into hex matrices, then print them.

        This function combines the two steps of block extraction and matrix conversion.
        """
        hex_blocks = self.extract_hex_blocks()

        
        hex_blocks_combined = "\n".join(hex_blocks)

        
        processed_blocks = self.mk_hex_matrix(hex_blocks_combined)

        if processed_blocks:
            print("Extracted Hex Blocks as Matrices:")
            for block_label, matrix in processed_blocks:
                print(f"\n{block_label}")
                for row in matrix:
                    print(row)
        else:
            print("No hex blocks found!")

##========================================
#test function
if __name__ == "__main__":
    l=Log2matrix()
    l.log2matrix()