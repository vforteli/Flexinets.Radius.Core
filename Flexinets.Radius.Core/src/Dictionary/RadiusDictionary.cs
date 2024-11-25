using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace Flexinets.Radius.Core
{
    public class RadiusDictionary : IRadiusDictionary
    {
        internal Dictionary<byte, DictionaryAttribute> Attributes { get; set; } =
            new Dictionary<byte, DictionaryAttribute>();

        internal List<DictionaryVendorAttribute> VendorSpecificAttributes { get; set; } =
            new List<DictionaryVendorAttribute>();

        internal Dictionary<string, DictionaryAttribute> AttributeNames { get; set; } =
            new Dictionary<string, DictionaryAttribute>();


        /// <summary>
        /// Parse dictionary from string content in Radiator format
        /// </summary>
        public static IRadiusDictionary Parse(string dictionaryFileContent)
        {
            var radiusDictionary = new RadiusDictionary();
            var lines = dictionaryFileContent
                .Split(new[] { "\n", "\r\n" }, StringSplitOptions.RemoveEmptyEntries)
                .Select(l => l.Trim())
                .ToList();

            foreach (var line in lines.Where(l => l.StartsWith("Attribute")))
            {
                var lineParts = line.Split(new[] { '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                var attributeCode = Convert.ToByte(lineParts[1]);

                var attributeDefinition = new DictionaryAttribute(lineParts[2], attributeCode, lineParts[3]);
                radiusDictionary.Attributes[attributeCode] = attributeDefinition;
                radiusDictionary.AttributeNames[attributeDefinition.Name] = attributeDefinition;
            }

            foreach (var line in lines.Where(l => l.StartsWith("VendorSpecificAttribute")))
            {
                var lineParts = line.Split(new[] { '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                var vsa = new DictionaryVendorAttribute(
                    Convert.ToUInt32(lineParts[1]),
                    lineParts[3],
                    Convert.ToUInt32(lineParts[2]),
                    lineParts[4]);

                radiusDictionary.VendorSpecificAttributes.Add(vsa);
                radiusDictionary.AttributeNames[vsa.Name] = vsa;
            }

            return radiusDictionary;
        }


        /// <summary>
        /// Read and parse dictionary from file in Radiator format
        /// </summary>
        public static async Task<IRadiusDictionary> LoadAsync(string dictionaryFilePath) =>
            Parse(await Task.FromResult(File.ReadAllText(dictionaryFilePath)));


        /// <summary>
        /// Load the dictionary from a dictionary file
        /// </summary>
        [Obsolete("Use RadiusDictionary.LoadAsync instead")]
        public RadiusDictionary(string dictionaryFilePath, ILogger<RadiusDictionary> logger)
        {
            // todo shouldnt be doing stuff like this in a constructor...
            var dictionary = (RadiusDictionary)Parse(File.ReadAllText(dictionaryFilePath));

            Attributes = dictionary.Attributes;
            VendorSpecificAttributes = dictionary.VendorSpecificAttributes;
            AttributeNames = dictionary.AttributeNames;

            logger.LogInformation(
                "Parsed {Attributes.Count} attributes and {VendorSpecificAttributes.Count} vendor attributes from file",
                Attributes.Count, VendorSpecificAttributes.Count);
        }


        private RadiusDictionary()
        {
        }


        public DictionaryVendorAttribute GetVendorAttribute(uint vendorId, byte vendorCode) =>
            VendorSpecificAttributes.FirstOrDefault(o => o.VendorId == vendorId && o.VendorCode == vendorCode);


        public DictionaryAttribute GetAttribute(byte typecode) =>
            Attributes.TryGetValue(typecode, out var attribute) ? attribute : null;


        public DictionaryAttribute GetAttribute(string name) =>
            AttributeNames.TryGetValue(name, out var attribute) ? attribute : null;
    }
}