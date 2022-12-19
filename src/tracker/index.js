const { iouAreas } = require('./utils');
const { ItemTracked, reset } = require('./ItemTracked');
const { munkresAlgorithm } = require('./trackAlgorithms/munkres');
const { kdTreeAlgorithm } = require('./trackAlgorithms/kdTree');

const DEBUG_MODE = false;

// Distance function
const iouDistance = function (item1, item2) {
  // IOU distance, between 0 and 1
  // The smaller, the less overlap
  const iou = iouAreas(item1, item2);

  // Invert this as the KDTREESEARCH is looking for the smaller value
  let distance = 1 - iou;

  // If the overlap is iou < 0.95, exclude value
  if (distance > (1 - params.iouLimit)) {
    distance = params.distanceLimit + 1;
  }

  return distance;
};

const params = {
  // DEFAULT_UNMATCHEDFRAMES_TOLERANCE
  // This the number of frame we wait when an object isn't matched before considering it gone
  unMatchedFramesTolerance: 5,
  // DEFAULT_IOU_LIMIT, exclude things from beeing matched if their IOU is lower than this
  // 1 means total overlap whereas 0 means no overlap
  iouLimit: 0.05,
  // Remove new objects fast if they could not be matched in the next frames.
  // Setting this to false ensures the object will stick around at least
  // unMatchedFramesTolerance frames, even if they could neven be matched in
  // subsequent frames.
  fastDelete: true,
  // The function to use to determine the distance between to detected objects
  distanceFunc: iouDistance,
  // The distance limit for matching. If values need to be excluded from
  // matching set their distance to something greater than the distance limit
  distanceLimit: 10000,
  // The algorithm used to match tracks with new detections. Can be either
  // 'kdTree' or 'munkres'.
  matchingAlgorithm: 'munkres',
  // matchingAlgorithm: 'kdTree',
};

// A dictionary of itemTracked currently tracked
// key: uuid
// value: ItemTracked object
let mapOfItemsTracked = new Map();

// A dictionary keeping memory of all tracked object (even after they disappear)
// Useful to ouput the file of all items tracked
let mapOfAllItemsTracked = new Map();

// By default, we do not keep all the history in memory
let keepAllHistoryInMemory = false;

exports.computeDistance = iouDistance;

exports.updateTrackedItemsWithNewFrame = function (detectionsOfThisFrame, frameNb) {
  const treeItemsTracked = kdTreeAlgorithm().rebuildTree(mapOfItemsTracked, params.distanceFunc);

  // SCENARIO 1: itemsTracked map is empty
  if (mapOfItemsTracked.size === 0) {
    // Just add every detected item as item Tracked
    detectionsOfThisFrame.forEach((itemDetected) => {
      const newItemTracked = new ItemTracked(itemDetected, frameNb, params.unMatchedFramesTolerance, params.fastDelete);
      // Add it to the map
      mapOfItemsTracked.set(newItemTracked.id, newItemTracked);
      // Add it to the kd tree
      treeItemsTracked.insert(newItemTracked);
    });
  }
  // SCENARIO 2: We already have itemsTracked in the map
  else {
    const matchedList = new Array(detectionsOfThisFrame.length);
    matchedList.fill(false);
    // Match existing Tracked items with the items detected in the new frame
    // For each look in the new detection to find the closest match
    if (detectionsOfThisFrame.length > 0) {
      let matchingAlgorithmFactory;
      switch (params.matchingAlgorithm) {
        case 'munkres':
          matchingAlgorithmFactory = munkresAlgorithm;
          break;
        case 'kdtree':
          matchingAlgorithmFactory = kdTreeAlgorithm;
          break;
        default:
          throw new Error(`Unknown matching algorithm ${params.matchingAlgorithm}`);
      }

      matchingAlgorithmFactory().generatedMatchedList(mapOfItemsTracked, params, detectionsOfThisFrame, matchedList, frameNb, DEBUG_MODE);
    } else {
      if (DEBUG_MODE) {
        console.log(`[Tracker] Nothing detected for frame nº${frameNb}`);
      }
      // Make existing tracked item available for deletion (to avoid ghost)
      mapOfItemsTracked.forEach((itemTracked) => {
        itemTracked.makeAvailable();
      });
    }

    // Start killing the itemTracked (and predicting next position)
    // that are tracked but haven't been matched this frame
    mapOfItemsTracked.forEach((itemTracked) => {
      if (itemTracked.available) {
        itemTracked.countDown(frameNb);
        itemTracked.updateTheoricalPositionAndSize();
        if (itemTracked.isDead()) {
          mapOfItemsTracked.delete(itemTracked.id);
          treeItemsTracked.remove(itemTracked);
          if (keepAllHistoryInMemory) {
            mapOfAllItemsTracked.set(itemTracked.id, itemTracked);
          }
        }
      }
    });
  }
};

exports.reset = function () {
  mapOfItemsTracked = new Map();
  mapOfAllItemsTracked = new Map();
  reset();
};

exports.setParams = function (newParams) {
  Object.keys(newParams).forEach((key) => {
    params[key] = newParams[key];
  });
};

exports.enableKeepInMemory = function () {
  keepAllHistoryInMemory = true;
};

exports.disableKeepInMemory = function () {
  keepAllHistoryInMemory = false;
};

exports.getJSONOfTrackedItems = function (roundInt = true) {
  return Array.from(mapOfItemsTracked.values()).map((itemTracked) => itemTracked.toJSON(roundInt));
};

exports.getJSONDebugOfTrackedItems = function (roundInt = true) {
  return Array.from(mapOfItemsTracked.values()).map((itemTracked) => itemTracked.toJSONDebug(roundInt));
};

exports.getTrackedItemsInMOTFormat = function (frameNb) {
  return Array.from(mapOfItemsTracked.values()).map((itemTracked) => itemTracked.toMOT(frameNb));
};

// Work only if keepInMemory is enabled
exports.getAllTrackedItems = function () {
  return mapOfAllItemsTracked;
};

// Work only if keepInMemory is enabled
exports.getJSONOfAllTrackedItems = function () {
  return Array.from(mapOfAllItemsTracked.values()).map((itemTracked) => itemTracked.toJSONGenericInfo());
};
