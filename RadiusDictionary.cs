using log4net;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Flexinets.Radius.Core
{
    public class RadiusDictionary
    {
        // todo hide these and create methods for retrieving attributes
        public Dictionary<Byte, DictionaryAttribute> Attributes { get; private set; } = new Dictionary<Byte, DictionaryAttribute>();
        public List<DictionaryVendorAttribute> VendorSpecificAttributes { get; private set; } = new List<DictionaryVendorAttribute>();
        public Dictionary<String, DictionaryAttribute> AttributeNames { get; private set; } = new Dictionary<string, DictionaryAttribute>();
        private readonly ILog _log = LogManager.GetLogger(typeof(RadiusDictionary));

            
        /// <summary>
        /// Create a dictionary with predefined lists, for example from a database
        /// </summary>
        /// <param name="attributes"></param>
        /// <param name="vendorSpecificAttributes"></param>
        public RadiusDictionary(List<DictionaryAttribute> attributes, List<DictionaryVendorAttribute> vendorSpecificAttributes)
        {
            Attributes = attributes.ToDictionary(o => o.Code);
            VendorSpecificAttributes = vendorSpecificAttributes;
        }


        /// <summary>
        /// Load the dictionary from a dictionary file
        /// </summary>        
        public RadiusDictionary(String dictionaryFilePath)
        {
            using (var sr = new StreamReader(dictionaryFilePath))
            {
                while (sr.Peek() >= 0)
                {
                    var line = sr.ReadLine();
                    if (line.StartsWith("Attribute"))
                    {
                        var lineparts = line.Split(new char[] { '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        var key = Convert.ToByte(lineparts[1]);

                        // If duplicates are encountered, the last one will prevail                        
                        if (Attributes.ContainsKey(key))
                        {
                            Attributes.Remove(key);
                        }
                        if (AttributeNames.ContainsKey(lineparts[2]))
                        {
                            AttributeNames.Remove(lineparts[2]);
                        }
                        var attributeDefinition = new DictionaryAttribute(lineparts[2], key, lineparts[3]);
                        Attributes.Add(key, attributeDefinition);
                        AttributeNames.Add(attributeDefinition.Name, attributeDefinition);
                    }

                    if (line.StartsWith("VendorSpecificAttribute"))
                    {
                        var lineparts = line.Split(new char[] { '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        var vsa = new DictionaryVendorAttribute(
                            Convert.ToUInt32(lineparts[1]),
                            lineparts[3],
                            Convert.ToUInt32(lineparts[2]),
                            lineparts[4]);

                        VendorSpecificAttributes.Add(vsa);

                        if (AttributeNames.ContainsKey(vsa.Name))
                        {
                            AttributeNames.Remove(vsa.Name);
                        }
                        AttributeNames.Add(vsa.Name, vsa);
                    }
                }

                _log.Info($"Parsed {Attributes.Count} attributes and {VendorSpecificAttributes.Count} vendor attributes from file");
            }
        }
    }
}
