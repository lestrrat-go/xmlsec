package xmlsec

func NewDSigCtx() (*DSigCtx, error) {
	return xmlSecDSigCtxCreate()
}

func (d *DSigCtx) Free() error {
	return xmlSecDSigCtxDestroy(d)
}
