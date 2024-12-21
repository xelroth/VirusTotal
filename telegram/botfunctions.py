import sys
sys.path.append(".")
from vt.vt import VirusTotalAPI

class VirusTotalAnalyzer:
    def __init__(self):
        self.vt_api = VirusTotalAPI()

    def __UploadFile__(self, file):
        """Uploads a file to VirusTotal and returns its hash."""
        return self.vt_api.__UploadFile__(file)

    def __CountTests__(self, analysis_results):
        """Counts the test results from the analysis."""
        d_count, u_count, n_count = 0, 0, 0
        detected, undetected, not_supported, d_results = [], [], [], []

        for result in analysis_results.results:
            if result.category == "malicious":
                d_count += 1
                detected.append(result.engine_name)
                d_results.append(result.result)
            elif result.category == "undetected":
                u_count += 1
                undetected.append(result.engine_name)
            else:
                n_count += 1
                not_supported.append(result.engine_name)

        return d_count, u_count, n_count, detected, undetected, not_supported, d_results

    def __CleanInfo__(self, file_hash):
        """Retrieves and formats file analysis information."""
        analysis_info = self.vt_api.__FileInfo__(file_hash)
        if analysis_info is None:
            print("File does not exist.")
            return None, None, None, None

        D, U, N, DL, UL, NL, DR = self.__CountTests__(analysis_info)

        front_text = (f'🧬 **Detections**: __{D} / {D + U}__\n\n'
                      f'🔖 **File Name**: __{analysis_info.filename}__\n'
                      f'🔒 **File Type**: __{analysis_info.type_description} ({analysis_info.file_type_info["file_type"]})__\n'
                      f'📁 **File Size**: __{pow(2, -20) * analysis_info.size:.2f} MB__\n'
                      f'⏱ **Times Submitted**: __{analysis_info.times_submitted}__\n\n'
                      f'🔬 **First Analysis**\n• __{analysis_info.first_submission_date}__\n'
                      f'🔭 **Last Analysis**\n• __{analysis_info.last_modification_date}__\n\n'
                      f'🎉 **Magic**\n• __{analysis_info.magic}__')

        test_text = '**❌ - Malicious\n✅ - Undetected\n⚠️ - Not Supported**\n➖➖➖➖➖➖➖➖➖➖\n'
        for engine in DL:
            test_text += f'❌ {engine}\n'
        for engine in UL:
            test_text += f'✅ {engine}\n'
        for engine in NL:
            test_text += f'⚠️ {engine}\n'

        signatures = ''.join(f'❌ {DL[i]}\n╰ {DR[i]}\n' for i in range(len(DR))) if D > 0 else "✅ Your File is Safe"

        link = f'https://virustotal.com/gui/file/{file_hash}'
        return front_text, test_text, signatures, link

