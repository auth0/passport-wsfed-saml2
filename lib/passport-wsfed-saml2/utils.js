

function getReqUrl(req){
  return req.protocol + '://' + (req.get('x-forwarded-host') || req.get('host')) + req.originalUrl;
}

module.exports = {
  getReqUrl : getReqUrl
}