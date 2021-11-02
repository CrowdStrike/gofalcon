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
					params.Offset = nil
					params.Filter = nil
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
					params.Offset = nil
					params.Filter = nil
				}
			}
		}
	}
}
