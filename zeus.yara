
rule Zbot{
	meta:
		author = "Jackson McCullough"
		description = "detection ruling on Zeus Banking Trojan 26Nov2013 version"
	
	strings:
		$fileName = "invoice_2318362983713_823931342io.pdf.exe"
		
		//unique functions 
		
		$peByte = "MZ"
		 $s1 = "Dumpcotsavo" ascii
		 $s1Hex={44 75 6D 70 63 6F 74 73 61 76 6F}
		 
		 $s2 = "BardHolyawe" ascii
		 $s2Hex = {42 61 72 64 48 6F 6C 79 61 77 65}
		 
		 $s3 = "SHLWAPI.dll" ascii
	     $s3Hex = {53 48 4C 57 41 50 49 2E 64 6C 6C}
		
       
		 
       
	   
	condition: //what has to be met for the malware to "meet" the Zbot or Zeus rule
		$peByte and $fileName
		and $s1 or $s1Hex
		and $s2 or $s2Hex
		and $s3 or $s3Hex
	}