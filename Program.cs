using System;
using System.IO;
using System.Security.Cryptography;
using System.Net.Http.Headers;
using Newtonsoft.Json.Linq;
using iTextSharp.text.pdf;
using System.Collections.Generic;
using System.IO;
namespace FileHash
{
    abstract class PDF_Library
    {
        public abstract List<MemoryStream> GetAttachments(string pdfFilePath);
        public abstract bool IsPdfFile(string filePath);
    }
     class iText_PDF_Library: PDF_Library
    {
        public override List<MemoryStream> GetAttachments(string pdfFilePath)
        {
            List<MemoryStream> attachments = new List<MemoryStream>();

            PdfReader reader = new PdfReader(pdfFilePath);
            PdfDictionary root = reader.Catalog;
            PdfDictionary names = root.GetAsDict(PdfName.NAMES);
            if (names == null) return attachments;

            PdfDictionary embeddedFiles = names.GetAsDict(PdfName.EMBEDDEDFILES);
            if (embeddedFiles == null) return attachments;

            PdfArray filespecs = embeddedFiles.GetAsArray(PdfName.NAMES);
            if (filespecs == null || filespecs.Size == 0) return attachments;

            for (int i = 0; i < filespecs.Size; i += 2)
            {
                PdfDictionary filespec = filespecs.GetAsDict(i);
                PdfDictionary refs = filespec.GetAsDict(PdfName.EF);
                if (refs == null) continue;

                foreach (PdfName key in refs.Keys)
                {
                    PRStream stream = (PRStream)PdfReader.GetPdfObject(refs.GetAsIndirectObject(key));
                    if (stream == null) continue;

                    // Create a MemoryStream and write the file content to it
                    MemoryStream attachmentStream = new MemoryStream(stream.GetBytes()); 
                    attachmentStream.Position = 0;
                    attachments.Add(attachmentStream);
                }
            }

            return attachments;
        }
        public override bool IsPdfFile(string filePath)
        {
            try
            {
                // Create a PdfReader object to read the PDF file
                PdfReader reader = new PdfReader(filePath);

                // Close the PdfReader object
                reader.Close();

                // If no exception occurred while creating PdfReader object, return true
                return true;
            }
            catch
            {
                // If an exception occurred while creating PdfReader object, return false
                return false;
            }
        }
    }
    class VirusTotalAPI
    {
        public async Task<bool> scanFile(string hash)
        {
            HttpClient client = new HttpClient();
            String uri = String.Format("https://www.virustotal.com/api/v3/files/{0}", hash);
            HttpRequestMessage request = new HttpRequestMessage
            {
                Method = HttpMethod.Get,
                RequestUri = new Uri(uri),
                Headers =
                {
                    { "accept", "application/json" },
                    { "x-apikey", "0c45cb0ef523eda9f103c354597a1e8986fb4640885f9c675bfc32e4c279bd42" },
                },
            };
            using (var response = await client.SendAsync(request))
            {
                try
                {
                    response.EnsureSuccessStatusCode();
                    var body = await response.Content.ReadAsStringAsync();
                    JObject jsonResponse = JObject.Parse(body);

                    if (jsonResponse["data"]["attributes"]["last_analysis_stats"]["malicious"] != null)
                    {
                        string maliciousCountStr = (string)jsonResponse["data"]["attributes"]["last_analysis_stats"]["malicious"];
                        int maliciousCount = Int32.Parse(maliciousCountStr);
                        return maliciousCount > 0 ? true : false;
                    }
                    else
                    {
                        return false;
                    }
                } catch (Exception ex) //ToDo: use 404notfound exception
                {
                    Console.WriteLine(ex.Message);
                    return false; //virus total returned exception
                }
                
            }
        }
    }
    class HashCalculator
    {

        public byte[] getFileData(string filePath)
        {
            return File.ReadAllBytes(filePath);
        }
        public string calculateHash(byte[] fileData)
        {
            string hash = String.Empty;
            try
            {
                byte[] hashData = SHA1.Create().ComputeHash(fileData);
                hash = BitConverter.ToString(hashData).Replace("-", string.Empty);
                Console.WriteLine("SHA-1 hash of the file: " + hash);
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred: " + ex.Message);
            }
            return hash;
        }
    }
    class Program
    {

        static async Task Main(string[] args)
        {
                //string filePath = "C:\\Users\\sunny\\downloads\\prorat_v1.9\\ProRat.exe";
                string filePath = "C:\\Users\\sunny\\downloads\\Macroeconomics.pdf";

                HashCalculator hashCalculator = new HashCalculator();
                string hash = hashCalculator.calculateHash(hashCalculator.getFileData(filePath));

                VirusTotalAPI virusTotalAPI = new VirusTotalAPI();
                bool isMalicious = await virusTotalAPI.scanFile(hash);

                Console.WriteLine("File {0} is malicious: {1}", filePath, isMalicious);
                
                PDF_Library pdflib = new iText_PDF_Library();
                if(File.Exists(filePath) && pdflib.IsPdfFile(filePath))
                {
                    var streamList = pdflib.GetAttachments(filePath);
                    foreach (var stream in streamList)
                    {
                        string attahcment_hash = hashCalculator.calculateHash(hashCalculator.getFileData(filePath));
                        bool isattchmentMalicious = await virusTotalAPI.scanFile(attahcment_hash);
                        Console.WriteLine("File {0} is malicious: {1}", filePath, isMalicious);
                    }
                }

        }
    }
}
