

function getReqUrl(req){
  return req.protocol + '://' + req.get('host') + req.originalUrl;
}

module.exports = {
  getReqUrl : getReqUrl
}