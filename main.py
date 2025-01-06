import os
import res_smbiosConfig
import fun_analyzeLog
import fun_log2matrix
import argparse

class EventLogAnalyzer:
    """
    A class to analyze event logs, process hex data, and detect SMBIOS Type 15 entries.
    """ 
    def __init__(self, log_file_path:str):
        """
        Initialize the EventLogAnalyzer with required configurations.

        :param log_file_path: Path to the log file to analyze.
        """
        self.type15 = res_smbiosConfig.SmbiosType15()
        self.analyzer = fun_analyzeLog.SmbiosAnalyzer()
        self.log2matrix = fun_log2matrix.Log2matrix(file_path=log_file_path)
        self.output_log = []

    def process_hex_blocks(self)->list:
        """
        Process the log file to extract and convert hex blocks into a usable format.

        :return: A list of processed hex blocks as matrices.
        """
        hex_blocks = self.log2matrix.extract_hex_blocks()
        hex_blocks_combined = "\n".join(hex_blocks)
        processed_blocks = self.log2matrix.mk_hex_matrix(hex_blocks_combined)
        return processed_blocks

    def analyze_block(self, block_label:list, matrix:list):
        """
        Analyze the hex matrix of a block, determine if it is Type 15, and log results.

        :param block_label: The label of the current hex block.
        :param matrix: The hex data matrix for the block.
        """
        if self.analyzer.type15_matrix(matrix):
            result = [f"\n{block_label} (Type 15 Detected):"]
            results = self.analyzer.hex_analyze(matrix)
            result.extend(results)
            
        else:
            result = [f"\n{block_label} (Not Type 15)"]

       
        self.output_log.extend(result)
        for result in self.output_log:
                print(result)

    def save_to_log_file(self):
        """
        Save the analysis results to a .log file in the current directory.
        """
        log_file_path = os.path.join(os.getcwd(), "analysis_result.log")
        with open(log_file_path, "w", encoding="utf-8") as log_file:
            log_file.write("\n".join(self.output_log))
        print(f"\nAnalysis results saved to: {log_file_path}")

    def main(self):
        """
        Main entry point to process the log file, analyze blocks, and save results.
        """
        processed_blocks = self.process_hex_blocks()

        if not processed_blocks:
            print("No hex blocks found!")
            self.output_log.append("No hex blocks found!")
            self.save_to_log_file()
            return

        print("Extracted Hex Blocks as Matrices:")
        self.output_log.append("Extracted Hex Blocks as Matrices:")
        none_type15_count = 0

        for block_label, matrix in processed_blocks:
            if self.analyzer.type15_matrix(matrix):
                self.analyze_block(block_label, matrix)
            else:
                none_type15_count += 1
                self.output_log.append(f"\n{block_label} (Not Type 15)")

        self.output_log.append(f"\n\nNumber of non-Type 15 blocks: {none_type15_count}")
        print(f"\n\n\033[31mNumber of non-Type 15 blocks: {none_type15_count}\033[0m")

        
        self.save_to_log_file()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Event log analyzer",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "addres", 
        help="Enter the complete file address,ex:D:\VScode\project\event_log\example\1224smbios.log"
    )
    
    args = parser.parse_args()
    log_file_path = fr"{args.addres}"
    analyzer = EventLogAnalyzer(log_file_path)
    analyzer.main()