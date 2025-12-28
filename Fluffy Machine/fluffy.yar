rule suspiciousSMBFileUpload {
	
	meta:
		description: "Detecting malicious .library-ms files get processed and which sends NTLM authentication hashes when visiting external SMB shares"
		author: "Pavan Mandapakala"
		reference: "CVE-2025-24071"
		date: "2028-12-2025"
		
	
	strings: 
		$xmlHeader = "<?xml version="1.0" encoding="UTF-8"?>"
		$libraryDescription = "<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">"
		$searchConnectorTag = "<searchConnectorDescriptionList>"
		$remoteURL = "<url>\\\\([0-9]{1,3}\.){3}[0-9]{1,3}[^<]*<\/url>"
	
	condition: 
		all of ($xmlHeader, $libraryDescription, $searchConnectorString, $remoteURL)
}

rule maliciousZipFiles {
	meta:
		description: "Detecting zip files with malicious windows library files"
		author: "Pavan Mandapakala"
		reference: "CVE-2025-24071"
		date: "28-12-2025"
		
	strings:
		$xmlHeader = "<?xml version="1.0" encoding="UTF-8"?>"
		$libraryDescription = "<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">"
		$searchConnectorTag = "<searchConnectorDescriptionList>"
		$remoteURL = "<url>\\\\([0-9]{1,3}\.){3}[0-9]{1,3}[^<]*<\/url>"
		$zipMagicBytes = { 50 4B 03 04 }
		$libraryExtension = ".library-ms" 
	
	condition:
		all of ($xmlHeader, $libraryDescription, $searchConnectorString, $remoteURL) and $zipMagicBytes at 0 and $libraryExtension
}
