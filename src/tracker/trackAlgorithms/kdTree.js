const isEqual = require('lodash.isequal');
const { kdTree } = require('kd-tree-javascript');
const { ItemTracked } = require('../ItemTracked');

// A kd-tree containing all the itemtracked
// Need to rebuild on each frame, because itemTracked positions have changed
const rebuildTree = (mapOfItemsTracked, distanceFunc) => new kdTree(Array.from(mapOfItemsTracked.values()), distanceFunc, ['x', 'y', 'w', 'h']);

const generatedMatchedList = (mapOfItemsTracked, params, detectionsOfThisFrame, matchedList, frameNb, DEBUG_MODE = false) => {
  // Contruct a kd tree for the detections of this frame
  const treeDetectionsOfThisFrame = new kdTree(detectionsOfThisFrame, params.distanceFunc, ['x', 'y', 'w', 'h']);

  mapOfItemsTracked.forEach((itemTracked) => {
    // First predict the new position of the itemTracked
    const predictedPosition = itemTracked.predictNextPosition();

    // Make available for matching
    itemTracked.makeAvailable();

    // Search for a detection that matches
    const treeSearchResult = treeDetectionsOfThisFrame.nearest(predictedPosition, 1, params.distanceLimit)[0];

    // Only for debug assessments of predictions
    const treeSearchResultWithoutPrediction = treeDetectionsOfThisFrame.nearest(itemTracked, 1, params.distanceLimit)[0];
    // Only if we enable the extra refinement
    const treeSearchMultipleResults = treeDetectionsOfThisFrame.nearest(predictedPosition, 2, params.distanceLimit);

    // If we have found something
    if (treeSearchResult) {
      // This is an extra refinement that happens in 0.001% of tracked items matching
      // If IOU overlap is super similar for two potential match, add an extra check
      // if(treeSearchMultipleResults.length === 2) {

      //   const indexFirstChoice = 0;
      //   if(treeSearchMultipleResults[0][1] > treeSearchMultipleResults[1][1]) {
      //     indexFirstChoice = 1;
      //   }

      //   const detectionFirstChoice = {
      //     bbox: treeSearchMultipleResults[indexFirstChoice][0],
      //     distance: treeSearchMultipleResults[indexFirstChoice][1]
      //   }

      //   const detectionSecondChoice = {
      //     bbox: treeSearchMultipleResults[1 - indexFirstChoice][0],
      //     distance: treeSearchMultipleResults[1 - indexFirstChoice][1]
      //   }

      //   const deltaDistance = Math.abs(detectionFirstChoice.distance - detectionSecondChoice.distance);

      //   if(deltaDistance < 0.05) {

      //     detectionFirstChoice.area = detectionFirstChoice.bbox.w * detectionFirstChoice.bbox.h;
      //     detectionSecondChoice.area = detectionSecondChoice.bbox.w * detectionSecondChoice.bbox.h;
      //     const itemTrackedArea = itemTracked.w * itemTracked.h;

      //     const deltaAreaFirstChoice = Math.abs(detectionFirstChoice.area - itemTrackedArea) / (detectionFirstChoice.area + itemTrackedArea);
      //     const deltaAreaSecondChoice = Math.abs(detectionSecondChoice.area - itemTrackedArea) / (detectionSecondChoice.area + itemTrackedArea);

      //     // Compare the area of each, priorize the detections that as a overal similar area
      //     // even if it overlaps less
      //     if(deltaAreaFirstChoice > deltaAreaSecondChoice) {
      //       if(Math.abs(deltaAreaFirstChoice - deltaAreaSecondChoice) > 0.5) {
      //         if(DEBUG_MODE) {
      //           console.log('Switch choice ! wise it seems different for frame: ' + frameNb + ' itemTracked ' + itemTracked.idDisplay)
      //           console.log(Math.abs(deltaAreaFirstChoice - deltaAreaSecondChoice));
      //         }
      //         // Change tree search result:
      //         treeSearchResult = treeSearchMultipleResults[1 - indexFirstChoice]
      //       }
      //     }
      //   }
      // }

      if (DEBUG_MODE) {
        // Assess different results between predition or not
        if (!isEqual(treeSearchResult[0], treeSearchResultWithoutPrediction && treeSearchResultWithoutPrediction[0])) {
          console.log('Making the pre-prediction led to a difference result:');
          console.log(`For frame ${frameNb} itemNb ${itemTracked.idDisplay}`);
        }
      }

      const indexClosestNewDetectedItem = detectionsOfThisFrame.indexOf(treeSearchResult[0]);
      // If this detections was not already matched to a tracked item
      // (otherwise it would be matched to two tracked items...)
      if (!matchedList[indexClosestNewDetectedItem]) {
        matchedList[indexClosestNewDetectedItem] = {
          idDisplay: itemTracked.idDisplay,
        };
        // Update properties of tracked object
        const updatedTrackedItemProperties = detectionsOfThisFrame[indexClosestNewDetectedItem];
        mapOfItemsTracked.get(itemTracked.id)
          .makeUnavailable()
          .update(updatedTrackedItemProperties, frameNb);
      } else {
        // Means two already tracked item are concurrent to get assigned a new detections
        // Rule is to priorize the oldest one to avoid id-reassignment
      }
    }

    // Add any unmatched items as new trackedItem only if those new items are not too similar
    // to existing trackedItems this avoids adding some double match of YOLO and bring down drasticly reassignments
    if (mapOfItemsTracked.size > 0) { // Safety check to see if we still have object tracked (could have been deleted previously)
      // Rebuild tracked item tree to take in account the new positions
      treeItemsTracked = new kdTree(Array.from(mapOfItemsTracked.values()), params.distanceFunc, ['x', 'y', 'w', 'h']);
      // console.log(`Nb new items Unmatched : ${matchedList.filter((isMatched) => isMatched === false).length}`)
      matchedList.forEach((matched, index) => {
        // Iterate through unmatched new detections
        if (!matched) {
          // Do not add as new tracked item if it is to similar to an existing one
          const treeSearchResult = treeItemsTracked.nearest(detectionsOfThisFrame[index], 1, params.distanceLimit)[0];

          if (!treeSearchResult) {
            const newItemTracked = ItemTracked(detectionsOfThisFrame[index], frameNb, params.unMatchedFramesTolerance, params.fastDelete);
            // Add it to the map
            mapOfItemsTracked.set(newItemTracked.id, newItemTracked);
            // Add it to the kd tree
            treeItemsTracked.insert(newItemTracked);
            // Make unvailable
            newItemTracked.makeUnavailable();
          } else {
            // console.log('Do not add, its overlapping an existing object')
          }
        }
      });
    }
  });
};

exports.kdTreeAlgorithm = function () {
  return ({
    generatedMatchedList,
    rebuildTree,
  });
};
