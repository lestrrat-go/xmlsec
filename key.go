package xmlsec

func LoadKeyFromFile(file string, format KeyDataFormat) (*Key, error) {
	return xmlSecCryptoAppKeyLoad(file, format)
}
