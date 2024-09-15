/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: api/filter/ratelimit.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "filter/ratelimit.pb-c.h"
void   filter__token_bucket__init
                     (Filter__TokenBucket         *message)
{
  static const Filter__TokenBucket init_value = FILTER__TOKEN_BUCKET__INIT;
  *message = init_value;
}
size_t filter__token_bucket__get_packed_size
                     (const Filter__TokenBucket *message)
{
  assert(message->base.descriptor == &filter__token_bucket__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t filter__token_bucket__pack
                     (const Filter__TokenBucket *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &filter__token_bucket__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t filter__token_bucket__pack_to_buffer
                     (const Filter__TokenBucket *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &filter__token_bucket__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Filter__TokenBucket *
       filter__token_bucket__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Filter__TokenBucket *)
     protobuf_c_message_unpack (&filter__token_bucket__descriptor,
                                allocator, len, data);
}
void   filter__token_bucket__free_unpacked
                     (Filter__TokenBucket *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &filter__token_bucket__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   filter__local_rate_limit__init
                     (Filter__LocalRateLimit         *message)
{
  static const Filter__LocalRateLimit init_value = FILTER__LOCAL_RATE_LIMIT__INIT;
  *message = init_value;
}
size_t filter__local_rate_limit__get_packed_size
                     (const Filter__LocalRateLimit *message)
{
  assert(message->base.descriptor == &filter__local_rate_limit__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t filter__local_rate_limit__pack
                     (const Filter__LocalRateLimit *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &filter__local_rate_limit__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t filter__local_rate_limit__pack_to_buffer
                     (const Filter__LocalRateLimit *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &filter__local_rate_limit__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Filter__LocalRateLimit *
       filter__local_rate_limit__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Filter__LocalRateLimit *)
     protobuf_c_message_unpack (&filter__local_rate_limit__descriptor,
                                allocator, len, data);
}
void   filter__local_rate_limit__free_unpacked
                     (Filter__LocalRateLimit *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &filter__local_rate_limit__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor filter__token_bucket__field_descriptors[3] =
{
  {
    "max_tokens",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_INT64,
    0,   /* quantifier_offset */
    offsetof(Filter__TokenBucket, max_tokens),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "tokens_per_fill",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_INT64,
    0,   /* quantifier_offset */
    offsetof(Filter__TokenBucket, tokens_per_fill),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "fill_interval",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_INT64,
    0,   /* quantifier_offset */
    offsetof(Filter__TokenBucket, fill_interval),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned filter__token_bucket__field_indices_by_name[] = {
  2,   /* field[2] = fill_interval */
  0,   /* field[0] = max_tokens */
  1,   /* field[1] = tokens_per_fill */
};
static const ProtobufCIntRange filter__token_bucket__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor filter__token_bucket__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "filter.TokenBucket",
  "TokenBucket",
  "Filter__TokenBucket",
  "filter",
  sizeof(Filter__TokenBucket),
  3,
  filter__token_bucket__field_descriptors,
  filter__token_bucket__field_indices_by_name,
  1,  filter__token_bucket__number_ranges,
  (ProtobufCMessageInit) filter__token_bucket__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor filter__local_rate_limit__field_descriptors[1] =
{
  {
    "token_bucket",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Filter__LocalRateLimit, token_bucket),
    &filter__token_bucket__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned filter__local_rate_limit__field_indices_by_name[] = {
  0,   /* field[0] = token_bucket */
};
static const ProtobufCIntRange filter__local_rate_limit__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 1 }
};
const ProtobufCMessageDescriptor filter__local_rate_limit__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "filter.LocalRateLimit",
  "LocalRateLimit",
  "Filter__LocalRateLimit",
  "filter",
  sizeof(Filter__LocalRateLimit),
  1,
  filter__local_rate_limit__field_descriptors,
  filter__local_rate_limit__field_indices_by_name,
  1,  filter__local_rate_limit__number_ranges,
  (ProtobufCMessageInit) filter__local_rate_limit__init,
  NULL,NULL,NULL    /* reserved[123] */
};
