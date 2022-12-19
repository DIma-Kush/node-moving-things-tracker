const munkres = require('munkres-js');
const { ItemTracked } = require('../ItemTracked');

const generatedMatchedList = (mapOfItemsTracked, params, detectionsOfThisFrame, matchedList, frameNb) => {
  const trackedItemIds = Array.from(mapOfItemsTracked.keys());

  const costMatrix = Array.from(mapOfItemsTracked.values())
    .map((itemTracked) => {
      const predictedPosition = itemTracked.predictNextPosition();
      return detectionsOfThisFrame.map(
        (detection) => params.distanceFunc(predictedPosition, detection),
      );
    });

  mapOfItemsTracked.forEach((itemTracked) => {
    itemTracked.makeAvailable();
  });

  munkres(costMatrix)
    .filter((m) => costMatrix[m[0]][m[1]] <= params.distanceLimit)
    .forEach((m) => {
      const itemTracked = mapOfItemsTracked.get(trackedItemIds[m[0]]);
      const updatedTrackedItemProperties = detectionsOfThisFrame[m[1]];
      matchedList[m[1]] = { idDisplay: itemTracked.idDisplay };
      itemTracked
        .makeUnavailable()
        .update(updatedTrackedItemProperties, frameNb);
    });

  matchedList.forEach((matched, index) => {
    if (!matched) {
      if (Math.min(...costMatrix.map((m) => m[index])) > params.distanceLimit) {
        const newItemTracked = ItemTracked(detectionsOfThisFrame[index], frameNb, params.unMatchedFramesTolerance, params.fastDelete);
        mapOfItemsTracked.set(newItemTracked.id, newItemTracked);
        newItemTracked.makeUnavailable();
        costMatrix.push(detectionsOfThisFrame.map(
          (detection) => params.distanceFunc(newItemTracked, detection),
        ));
      }
    }
  });
};

exports.munkresAlgorithm = function () {
  return ({
    generatedMatchedList,
  });
};
