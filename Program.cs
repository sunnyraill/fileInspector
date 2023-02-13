using System;
using System.IO;
using System.Security.Cryptography;
using System.Net.Http.Headers;
using Newtonsoft.Json.Linq;

namespace FileHash
{
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
                response.EnsureSuccessStatusCode();
                var body = await response.Content.ReadAsStringAsync();
                JObject jsonResponse = JObject.Parse(body);
                
                if (jsonResponse["data"]["attributes"]["last_analysis_stats"]["malicious"] != null)
                {
                    string maliciousCountStr = (string)jsonResponse["data"]["attributes"]["last_analysis_stats"]["malicious"];
                    int maliciousCount = Int32.Parse(maliciousCountStr);
                    return maliciousCount>0?true:false;
                }
                else
                {
                    return false;
                }
                //Console.WriteLine(body);
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
                string filePath = "C:\\Users\\sunny\\downloads\\prorat_v1.9\\ProRat.exe";

                HashCalculator hashCalculator = new HashCalculator();
                string hash = hashCalculator.calculateHash(hashCalculator.getFileData(filePath));

                VirusTotalAPI virusTotalAPI = new VirusTotalAPI();
                bool isMalicious = await virusTotalAPI.scanFile(hash);

                Console.WriteLine("File {0} is malicious: {1}", filePath, isMalicious);

        }
    }
}
