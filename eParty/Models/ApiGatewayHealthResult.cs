using Newtonsoft.Json;
using System.Collections.Generic;

namespace eParty.Models
{
    public class ApiGatewayHealthResult
    {
        [JsonProperty("status")]
        public string Status { get; set; }

        [JsonProperty("model_type")]
        public string ModelType { get; set; }

        [JsonProperty("features")]
        public List<string> Features { get; set; }

        [JsonProperty("labels")]
        public List<string> Labels { get; set; }

        public bool IsOnline { get; set; }

        public string ErrorMessage { get; set; }

        public ApiGatewayHealthResult()
        {
            Features = new List<string>();
            Labels = new List<string>();
        }

        public static ApiGatewayHealthResult Offline(string error)
        {
            return new ApiGatewayHealthResult
            {
                IsOnline = false,
                Status = "offline",
                ModelType = "unknown",
                ErrorMessage = error
            };
        }
    }
}