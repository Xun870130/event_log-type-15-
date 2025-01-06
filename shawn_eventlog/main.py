import os
import res_smbiosConfig
import fun_analyzeLog
import fun_log2matrix
import argparse

class EventLogAnalyzer:
    def __init__(self, log_file_path:str):
       
        self.type15 = res_smbiosConfig.SmbiosType15()
        self.analyzer = fun_analyzeLog.SmbiosAnalyzer()
        self.log2matrix = fun_log2matrix.Log2matrix(file_path=log_file_path)
        self.output_log = []

    def process_hex_blocks(self)->list:
        """
        analyze hex data
        """
        hex_blocks = self.log2matrix.extract_hex_blocks()
        hex_blocks_combined = "\n".join(hex_blocks)
        processed_blocks = self.log2matrix.mk_hex_matrix(hex_blocks_combined)
        return processed_blocks

    def analyze_block(self, block_label:list, matrix:list):
        """
        Analyze the block matrix, detect Type 15 and parse its contents
        """
        if self.analyzer.type15_matrix(matrix):
            result = [f"\n{block_label} (Type 15 Detected):"]
            results = self.analyzer.hex_analyze(matrix)
            result.extend(results)
            
        else:
            result = [f"\n{block_label} (Not Type 15)"]

        # 將結果加入輸出日誌
        self.output_log.extend(result)
        for result in self.output_log:
                print(result)

    def save_to_log_file(self):
        """
        Save output results to log file in the current directory
        """
        log_file_path = os.path.join(os.getcwd(), "analysis_result.log")
        with open(log_file_path, "w", encoding="utf-8") as log_file:
            log_file.write("\n".join(self.output_log))
        print(f"\nAnalysis results saved to: {log_file_path}")

    def main(self):
        
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

        # 統計非 Type 15 的區塊數
        self.output_log.append(f"\n\nNumber of non-Type 15 blocks: {none_type15_count}")
        print(f"\n\n\033[31mNumber of non-Type 15 blocks: {none_type15_count}\033[0m")

        # 保存結果到 .log 文件
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
