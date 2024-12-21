import random
import json
import string
from datetime import datetime
from .module_class import AnalysisResults, AnalysisStats, FileInfo

class FileAnalyzer:
    
    @staticmethod
    def __GenerateRandomHeaderId__() -> str:
        """Generates a random header ID."""
        return "".join(random.choice(string.ascii_letters) for _ in range(59)) + "=="

    @staticmethod
    def __FillFileInfo__ (data: json, raw: int = 0) -> FileInfo:
        """Fills file information from the provided JSON data."""
        if raw:
            return data
        
        data = data["data"]
        file_type_info = {}
        total_votes = {}
        last_analysis_results = []
        tags = []

        file_type = data["type"]
        file_id = data["id"]
        attributes = data["attributes"]
        type_description = attributes["type_description"]

        for item in attributes["trid"]:
            file_type_info.update(
                {"file_type": item["file_type"], "probability": item["probability"]}
            )

        filename = attributes.get("names", [""])[0]
        last_modification_date = datetime.fromtimestamp(attributes["last_modification_date"])
        times_submitted = attributes["times_submitted"]

        total_votes.update(
            {
                "harmless": attributes["total_votes"]["harmless"],
                "malicious": attributes["total_votes"]["malicious"],
            }
        )
        
        size = attributes["size"]
        file_extension = attributes["type_extension"]
        last_submission_date = datetime.fromtimestamp(attributes["last_modification_date"])

        for _, value in attributes["last_analysis_results"].items():
            temp = {
                "engine_name": value["engine_name"],
                "engine_version": value["engine_version"],
                "result": value["result"],
                "category": value["category"]
            }
            last_analysis_results.append(AnalysisResults(**temp))

        list_hash = {
            "sha256": attributes["sha256"],
            "md5": attributes["md5"],
            "sha1": attributes["sha1"],
            "vhash": attributes.get("vhash"),
            "ssdeep": attributes.get("ssdeep"),
            "tlsh": attributes.get("tlsh"),
        }
        
        magic = attributes.get("magic")
        first_submission_date = datetime.fromtimestamp(attributes["first_submission_date"])
        tags.extend(attributes["tags"])
        last_analysis_date = datetime.fromtimestamp(attributes["last_analysis_date"])

        analysis_stats = attributes["last_analysis_stats"]
        last_analysis_stats = AnalysisStats(
            harmless=analysis_stats["harmless"],
            type_unsupported=analysis_stats["type-unsupported"],
            suspicious=analysis_stats["suspicious"],
            confirmed_timeout=analysis_stats["confirmed-timeout"],
            timeout=analysis_stats["timeout"],
            failure=analysis_stats["failure"],
            malicious=analysis_stats["malicious"],
            undetected=analysis_stats["undetected"],
        )

        file_info = {
            "filename": filename,
            "id": file_id,
            "type_description": type_description,
            "file_type_info": file_type_info,
            "first_submission_date": first_submission_date,
            "last_modification_date": last_modification_date,
            "times_submitted": times_submitted,
            "total_votes": total_votes,
            "size": size,
            "file_extension": file_extension,
            "last_submission_date": last_submission_date,
            "results": last_analysis_results,
            "tags": tags,
            "last_analysis_date": last_analysis_date,
            "list_hash": list_hash,
            "analysis_stats": last_analysis_stats,
            "file_type": file_type,
            "magic": magic,
        }

        return FileInfo(**file_info)

