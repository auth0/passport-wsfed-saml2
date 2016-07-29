

function getReqUrl(req){
  return req.protocol + '://' + (req.get('x-forwarded-host') || req.get('host')) + req.originalUrl;
}

function generateUniqueID() {
  var chars = "abcdef0123456789";
  var uniqueID = "";
  for (var i = 0; i < 20; i++) {
    uniqueID += chars.substr(Math.floor((Math.random()*15)), 1);
  }
  return uniqueID;
}

module.exports = {
  getReqUrl : getReqUrl,
  generateUniqueID: generateUniqueID
};