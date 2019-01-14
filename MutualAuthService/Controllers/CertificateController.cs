using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Specialized;

namespace MutualAuthService.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CertificateController : ControllerBase
    {
        // GET api/values
        [HttpGet]
        public ActionResult<IEnumerable<string>> Get()
        {
            Object returnObject=null;
            var headers = base.Request.Headers;
            string certHeader = headers["X-ARR-ClientCert"];
            string thumbprint = null;
            if (!String.IsNullOrEmpty(certHeader))
            {
                try
                {
                    byte[] clientCertBytes = Convert.FromBase64String(certHeader);
                    var certificate = new X509Certificate2(clientCertBytes);
                    thumbprint = certificate.Thumbprint;
                    returnObject = new
                    {
                        certificate.Subject,
                        certificate.Issuer,
                        certificate.Thumbprint,
                        SignatureAlg = certificate.SignatureAlgorithm.FriendlyName,
                        IssueDate = certificate.NotBefore.ToShortDateString() + " " + certificate.NotBefore.ToShortTimeString(),
                        ExpiryDate = certificate.NotAfter.ToShortDateString() + " " + certificate.NotAfter.ToShortTimeString()
                    };
                }
                catch (Exception ex)
                {
                    returnObject = new { Exception = ex.Message };
                }
                finally
                {
                    if (!IsValidClientCertificate(thumbprint)) Response.StatusCode = 403;
                    else Response.StatusCode = 200; 
                }
            }
            else
            {
                Response.StatusCode = 403;
                returnObject = new { Message = "No client certificate was provided" };
            }
            return new JsonResult(returnObject);
        }
        private bool IsValidClientCertificate(string thumbprint)
        {
            //if (thumbprint != "9C366E673B267E9BEB1DB32F42681102CA0BB100")
            //{
            //    return false;
            //}
            return true;
        }

    }
}
