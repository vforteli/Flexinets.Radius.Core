using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace Flexinets.Radius.Core
{
    public partial class RadiusDictionary : IRadiusDictionary
    {
        private readonly Dictionary<byte, DictionaryAttribute> _attributes;
        private readonly List<DictionaryVendorAttribute> _vendorSpecificAttributes;
        private readonly Dictionary<string, DictionaryAttribute> _attributeNames;

        private RadiusDictionary(
            Dictionary<byte, DictionaryAttribute> attributes,
            List<DictionaryVendorAttribute> vendorSpecificAttributes,
            Dictionary<string, DictionaryAttribute> attributeNames)
        {
            _attributes = attributes;
            _vendorSpecificAttributes = vendorSpecificAttributes;
            _attributeNames = attributeNames;
        }


        /// <summary>
        /// Parse dictionary from string content in Radiator format
        /// </summary>
        public static IRadiusDictionary Parse(string dictionaryFileContent)
        {
            var attributes = new Dictionary<byte, DictionaryAttribute>();
            var vendorSpecificAttributes = new List<DictionaryVendorAttribute>();
            var attributeNames = new Dictionary<string, DictionaryAttribute>();

            var lines = dictionaryFileContent
                .Split(new[] { "\n", "\r\n" }, StringSplitOptions.RemoveEmptyEntries)
                .Select(l => l.Trim())
                .ToList();

            foreach (var line in lines.Where(l => l.StartsWith("Attribute")))
            {
                var lineParts = line.Split(new[] { '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                var attributeCode = Convert.ToByte(lineParts[1]);

                var attributeDefinition = new DictionaryAttribute(lineParts[2], attributeCode, lineParts[3]);
                attributes[attributeCode] = attributeDefinition;
                attributeNames[attributeDefinition.Name] = attributeDefinition;
            }

            foreach (var line in lines.Where(l => l.StartsWith("VendorSpecificAttribute")))
            {
                var lineParts = line.Split(new[] { '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                var vsa = new DictionaryVendorAttribute(
                    Convert.ToUInt32(lineParts[1]),
                    lineParts[3],
                    Convert.ToUInt32(lineParts[2]),
                    lineParts[4]);

                vendorSpecificAttributes.Add(vsa);
                attributeNames[vsa.Name] = vsa;
            }

            return new RadiusDictionary(attributes, vendorSpecificAttributes, attributeNames);
        }


        /// <summary>
        /// Read and parse dictionary from file in Radiator format
        /// </summary>
        public static async Task<IRadiusDictionary> LoadAsync(string dictionaryFilePath) =>
            Parse(await File.ReadAllTextAsync(dictionaryFilePath));


        public DictionaryVendorAttribute? GetVendorAttribute(uint vendorId, byte vendorCode) =>
            _vendorSpecificAttributes.FirstOrDefault(o => o.VendorId == vendorId && o.VendorCode == vendorCode);


        public DictionaryAttribute? GetAttribute(byte typecode) => _attributes.GetValueOrDefault(typecode);


        public DictionaryAttribute? GetAttribute(string name) => _attributeNames.GetValueOrDefault(name);
    }
}