using System;
using System.IO;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using System.Net.Http;

namespace ScanUploadedBlobFunction
{
    public static class ScanUploadedBlob
    {
        private static ScannerProxy scanner = null;

        [FunctionName("ScanUploadedBlob")]
        public static void Run([BlobTrigger("%new_files_container_name%/{name}", Connection = "sftp_storage_conn")]Stream myBlob, string name, ILogger log)
        {
            log.LogInformation($"C# Blob trigger ScanUploadedBlob function Processed blob Name:{name} Size: {myBlob.Length} Bytes");
            
            if (scanner == null) {
                var scannerHost = Environment.GetEnvironmentVariable("av_vm_host");
                var scannerPort = Environment.GetEnvironmentVariable("av_vm_port");
                scanner = new ScannerProxy(log, scannerHost);
            }

            var scanResults = scanner.Scan(myBlob, name);
            if (scanResults == null)
            {
                return;
            }
            log.LogInformation($"Scan Results - {scanResults.ToString(", ")}");
            log.LogInformation("Handling Scan Results");
            var action = new Remediation(scanResults, log);
            action.Start();
            log.LogInformation($"ScanUploadedBlob function done Processing blob Name:{name} Size: {myBlob.Length} Bytes");
        }
    }
}
