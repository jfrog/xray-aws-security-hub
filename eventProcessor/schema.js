import Joi from 'joi';
import { getLogger } from './logger.js';

const logger = getLogger();

const MAX_NAME_CHARS_LIMIT = 255;
const MAX_PATH_CHARS_LIMIT = 4096;
const MAX_TEXT_CHARS_LIMIT = 3000;

const xraySchema = Joi.object({
  watch_name: Joi.string().max(MAX_NAME_CHARS_LIMIT).required(),
  policy_name: Joi.string().max(MAX_NAME_CHARS_LIMIT).required(),
  issues: Joi.array().items(Joi.object({
    severity: Joi.string().required().valid('Critical', 'High', 'Medium', 'Low', 'Information', 'Unknown'),
    type: Joi.string().required().valid('security', 'License', 'Operational Risk'),
    summary: Joi.string().max(MAX_TEXT_CHARS_LIMIT).truncate().required(),
    description: Joi.string().max(MAX_TEXT_CHARS_LIMIT).truncate().required(),
    impacted_artifacts: Joi.array().items(Joi.object({
      name: Joi.string().max(MAX_NAME_CHARS_LIMIT).required(),
      display_name: Joi.string().max(MAX_TEXT_CHARS_LIMIT).required(),
      path: Joi.string().max(MAX_PATH_CHARS_LIMIT).required(),
      pkg_type: Joi.string().max(MAX_NAME_CHARS_LIMIT).insensitive().required(),
      sha256: Joi.string().max(66),
      sha1: Joi.string().allow('').max(66),
      depth: Joi.number(),
      parent_sha: Joi.string().max(64),
      infected_files: Joi.array().items(Joi.object({
        name: Joi.string().max(MAX_NAME_CHARS_LIMIT),
        path: Joi.string().max(MAX_PATH_CHARS_LIMIT).required().allow(''),
        sha256: Joi.string().max(66),
        depth: Joi.number(),
        parent_sha: Joi.string().max(64),
        display_name: Joi.string().max(MAX_TEXT_CHARS_LIMIT),
        pkg_type: Joi.string().max(20),
      })).required(),
    })).default([]),
    applicability: Joi.string().allow(null),
    cve: Joi.string().pattern(/^CVE-\d{4}-\d{4,}$/), // https://cve.mitre.org/cve/identifiers/tech-guidance.html#extraction_or_parsing
  })),
}).required();

export async function validateSchema(xrayEvent) {
  try {
    return await xraySchema.validateAsync(xrayEvent, { allowUnknown: true, errors: { render: false } });
  } catch (e) {
    logger.error('schema validation failed', { error: e });
    const err = new Error('Invalid Xray event payload', { cause: e });
    err.statusCode = 400;
    throw err;
  }
}
