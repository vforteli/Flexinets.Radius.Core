using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Flexinets.Radius.Core
{    
    public class DictionaryVendorAttribute
    {
        public readonly UInt32 VendorId;
        public readonly String Name;
        public readonly UInt32 Code;
        public readonly String Type;


        /// <summary>
        /// Create a dictionary vendor specific attribute
        /// </summary>
        /// <param name="vendorId"></param>
        /// <param name="name"></param>
        /// <param name="code"></param>
        /// <param name="type"></param>
        public DictionaryVendorAttribute(UInt32 vendorId, String name, UInt32 code, String type)
        {
            VendorId = vendorId;
            Name = name;
            Code = code;
            Type = type;
        }
    }
}
