using System;
using System.IO;
using Microsoft.Extensions.Logging;

namespace Flexinets.Radius.Core
{
    public partial class RadiusDictionary
    {
        /// <summary>
        /// Load the dictionary from a dictionary file
        /// </summary>
        [Obsolete("Use RadiusDictionary.LoadAsync instead")]
        public RadiusDictionary(string dictionaryFilePath, ILogger<RadiusDictionary> logger)
        {
            // todo shouldnt be doing stuff like this in a constructor...
            var dictionary = (RadiusDictionary)Parse(File.ReadAllText(dictionaryFilePath));

            _attributes = dictionary._attributes;
            _vendorSpecificAttributes = dictionary._vendorSpecificAttributes;
            _attributeNames = dictionary._attributeNames;

            logger.LogInformation(
                "Parsed {Attributes.Count} attributes and {VendorSpecificAttributes.Count} vendor attributes from file",
                _attributes.Count, _vendorSpecificAttributes.Count);
        }
    }
}