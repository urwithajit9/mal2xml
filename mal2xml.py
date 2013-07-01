#!/usr/bin/env python
'''
Copyright (C) 2013 Kevin Breen.
Mal2XML

'''
__description__ = 'Python script to save malware in an XML Format'
__author__ = 'Kevin Breen'
__version__ = '0.1'
__date__ = '2013/07/01'


import xml.etree.cElementTree as ET

import os
import base64
import hashlib
from optparse import OptionParser, OptionGroup


def main():
	parser = OptionParser(usage='usage: %prog [options] inputFile outputFile\n' + __description__, version='%prog ' + __version__)
	parser.add_option("-d", "--delete", action='store_true', default=False, help="Remove Original File")
	parser.add_option("-e", "--extract", action='store_true', default=False, help="extracts File from XML")
	(options, args) = parser.parse_args()
		
	if options.extract == True: # if we are extracting files 
		tree = ET.parse(args[0])
		root = tree.getroot()
		outName = root[0][0].attrib['name'] + root[0][0].attrib['ext']
		encodedData = root[0][1].text
		oldmd5 = root[0][0].text
		print oldmd5
		with open(outName, "a") as f:
			f.write(base64.b64decode(encodedData))
						
	else: # if we are inserting files
		fileName, fileExt = os.path.splitext(args[0])
		fileSize = str(os.path.getsize(args[0]))
		with open(args[0], 'rb') as fh:
			m = hashlib.md5()
			while True:
				data = fh.read(8192)
				if not data:
					break
				m.update(data)
			md5 = m.hexdigest() # Create the MD5 of the origional file, not the encoded data
		with open(args[0], 'rb') as fh:
			encoded = base64.b64encode(fh.read()) # Create the Base64 Encoded data to store

		# create the xml template and fill in the values
		MalStore = ET.Element("MalStore")
		malware = ET.SubElement(MalStore, "malware")
		fileData = ET.SubElement(malware, "fileData")
		fileData.set("size", fileSize)
		fileData.set("ext", fileExt)
		fileData.set("name", fileName)
		md5 = str(md5)
		fileData.text = md5
		rawData = ET.SubElement(malware, "Data")
		rawData.set("encoding", "base64")
		rawData.text = encoded
		tree = ET.ElementTree(MalStore)
		outname = args[1]
		tree.write(outname)
		if options.delete == True:
			os.path.remove(args[0])	
	
	
if __name__ == "__main__":
	main()	


