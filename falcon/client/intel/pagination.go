package intel

import (
	"github.com/go-openapi/runtime"
)

func (o *QueryIntelIndicatorEntitiesOK) HasNextPage() bool {
	return o == nil || o.NextPage != ""
}

func (o *QueryIntelIndicatorEntitiesOK) Paginate() ClientOption {
	return func(operation *runtime.ClientOperation) {
		if o != nil {
			if o.NextPage != "" {
				operation.PathPattern = o.NextPage
				params, ok := operation.Params.(*QueryIntelIndicatorEntitiesParams)
				if ok {
					operation.Params = &QueryIntelIndicatorEntitiesParams{
						Context:    params.Context,
						HTTPClient: params.HTTPClient,
						timeout:    params.timeout,
					}
				}
			}
		}
	}
}

func (o *QueryIntelIndicatorIdsOK) HasNextPage() bool {
	return o == nil || o.NextPage != ""
}

func (o *QueryIntelIndicatorIdsOK) Paginate() ClientOption {
	return func(operation *runtime.ClientOperation) {
		if o != nil {
			if o.NextPage != "" {
				operation.PathPattern = o.NextPage
				params, ok := operation.Params.(*QueryIntelIndicatorIdsParams)
				if ok {
					operation.Params = &QueryIntelIndicatorIdsParams{
						Context:    params.Context,
						HTTPClient: params.HTTPClient,
						timeout:    params.timeout,
					}
				}
			}
		}
	}
}
