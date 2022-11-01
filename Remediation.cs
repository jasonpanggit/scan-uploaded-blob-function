using Azure.Storage.Blobs;
using Microsoft.Extensions.Logging;
using System;
using System.Threading.Tasks;

namespace ScanUploadedBlobFunction
{
    public class Remediation
    {
        private ScanResults scanResults { get; }
        private ILogger log { get; }
        public Remediation(ScanResults scanResults, ILogger log)
        {
            this.scanResults = scanResults;
            this.log = log;
        }

        public void Start()
        {
            string newFilesContainerName = Environment.GetEnvironmentVariable("new_files_container_name");
            string cleanFilesContainerName = Environment.GetEnvironmentVariable("clean_files_container_name");
            string quarantineFilesContainerName = Environment.GetEnvironmentVariable("quarantine_files_container_name");
                    
            if (scanResults.isThreat)
            {
                log.LogInformation($"A malicious file was detected, file name: {scanResults.fileName}, threat type: {scanResults.threatType}");
                try
                {
                    MoveBlob(scanResults.fileName, newFilesContainerName, quarantineFilesContainerName, log).GetAwaiter().GetResult();
                    log.LogInformation($"A malicious file was detected. It has been moved from the {newFilesContainerName} container to the {quarantineFilesContainerName} container");
                }

                catch (Exception e)
                {
                    log.LogError($"A malicious file was detected, but moving it to the {quarantineFilesContainerName} container failed. {e.Message}");
                }
            }

            else
            {
                try
                {
                    MoveBlob(scanResults.fileName, newFilesContainerName, cleanFilesContainerName, log).GetAwaiter().GetResult();
                    log.LogInformation($"The file is clean. It has been moved from the {newFilesContainerName} container to the {cleanFilesContainerName} container");
                }

                catch (Exception e)
                {
                    log.LogError($"The file is clean, but moving it to the {cleanFilesContainerName} container failed. {e.Message}");
                }
            }
        }

        private static async Task MoveBlob(string srcBlobName, string srcContainerName, string destContainerName, ILogger log)
        {
            //Note: if the srcBlob name already exist in the dest container it will be overwritten
            
            var connectionString = Environment.GetEnvironmentVariable("sftp_storage_conn");
            var srcContainer = new BlobContainerClient(connectionString, srcContainerName);
            var destContainer = new BlobContainerClient(connectionString, destContainerName);
            destContainer.CreateIfNotExists();

            var srcBlob = srcContainer.GetBlobClient(srcBlobName);
            var destBlob = destContainer.GetBlobClient(srcBlobName);

            if (await srcBlob.ExistsAsync())
            {
                log.LogInformation("MoveBlob: Started file copy");
                await destBlob.StartCopyFromUriAsync(srcBlob.Uri);
                log.LogInformation("MoveBlob: Done file copy");
                await srcBlob.DeleteAsync();
                log.LogInformation("MoveBlob: Source file deleted");
            }
        }
    }
}
