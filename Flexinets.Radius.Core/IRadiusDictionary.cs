namespace Flexinets.Radius.Core
{
    public interface IRadiusDictionary
    {
        /// <summary>
        /// Get a vendor specific attribute by vendorId and vendorCode
        /// </summary>
        /// <param name="vendorId"></param>
        /// <param name="vendorCode"></param>
        /// <returns></returns>
        DictionaryVendorAttribute? GetVendorAttribute(uint vendorId, byte vendorCode);


        /// <summary>
        /// Get an RFC attribute by code
        /// </summary>
        /// <param name="code"></param>
        /// <returns></returns>
        DictionaryAttribute GetAttribute(byte code);


        /// <summary>
        /// Get an attribute or vendor attribute by name
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        DictionaryAttribute GetAttribute(string name);
    }
}