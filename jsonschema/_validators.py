import re

from jsonschema import _utils
from jsonschema.exceptions import FormatError, ValidationError
from jsonschema.compat import iteritems


def patternProperties(validator, patternProperties, instance, schema):
    if not validator.is_type(instance, "object"):
        return

    for pattern, subschema in iteritems(patternProperties):
        for k, v in iteritems(instance):
            if re.search(pattern, k):
                for error in validator.descend(
                    v, subschema, path=k, schema_path=pattern,
                ):
                    yield error


def additionalProperties(validator, aP, instance, schema):
    if not validator.is_type(instance, "object"):
        return

    extras = set(_utils.find_additional_properties(instance, schema))

    if validator.is_type(aP, "object"):
        for extra in extras:
            for error in validator.descend(instance[extra], aP, path=extra):
                yield error
    elif not aP and extras:
        if "patternProperties" in schema:
            patterns = sorted(schema["patternProperties"])
            if len(extras) == 1:
                verb = "does"
            else:
                verb = "do"
            error = "%s %s not match any of the regexes: %s" % (
                ", ".join(map(repr, sorted(extras))),
                verb,
                ", ".join(map(repr, patterns)),
            )
            yield ValidationError(error)
        else:
            error = "Additional properties are not allowed (%s %s unexpected)"
            yield ValidationError(error % _utils.extras_msg(extras))


def items(validator, items, instance, schema):
    if not validator.is_type(instance, "array"):
        return

    if validator.is_type(items, "object"):
        for index, item in enumerate(instance):
            for error in validator.descend(item, items, path=index):
                yield error
    else:
        for (index, item), subschema in zip(enumerate(instance), items):
            for error in validator.descend(
                item, subschema, path=index, schema_path=index,
            ):
                yield error


def additionalItems(validator, aI, instance, schema):
    if (
        not validator.is_type(instance, "array") or
        validator.is_type(schema.get("items", {}), "object")
    ):
        return

    len_items = len(schema.get("items", []))
    if validator.is_type(aI, "object"):
        for index, item in enumerate(instance[len_items:], start=len_items):
            for error in validator.descend(item, aI, path=index):
                yield error
    elif not aI and len(instance) > len(schema.get("items", [])):
        error = "Additional items are not allowed (%s %s unexpected)"
        yield ValidationError(
            error %
            _utils.extras_msg(instance[len(schema.get("items", [])):])
        )


def minimum(validator, minimum, instance, schema):
    if not validator.is_type(instance, "number") or not validator.is_type(minimum, "number"):
        return

    if schema.get("exclusiveMinimum", False):
        failed = instance <= minimum
        cmp = "less than or equal to"
    else:
        failed = instance < minimum
        cmp = "less than"

    if failed:
        yield ValidationError(
            "%r is %s the minimum of %r" % (instance, cmp, minimum)
        )


def maximum(validator, maximum, instance, schema):
    if not validator.is_type(instance, "number"):
        return

    if schema.get("exclusiveMaximum", False):
        failed = instance >= maximum
        cmp = "greater than or equal to"
    else:
        failed = instance > maximum
        cmp = "greater than"

    if failed:
        yield ValidationError(
            "%r is %s the maximum of %r" % (instance, cmp, maximum)
        )


def multipleOf(validator, dB, instance, schema):
    if not validator.is_type(instance, "number"):
        return

    if isinstance(dB, float):
        quotient = instance / dB
        failed = int(quotient) != quotient
    else:
        failed = instance % dB

    if failed:
        yield ValidationError("%r is not a multiple of %r" % (instance, dB))


def minItems(validator, mI, instance, schema):
    if validator.is_type(instance, "array") and len(instance) < mI:
        yield ValidationError("%r is too short" % (instance,))


def maxItems(validator, mI, instance, schema):
    if validator.is_type(instance, "array") and len(instance) > mI:
        yield ValidationError("%r is too long" % (instance,))


def uniqueItems(validator, uI, instance, schema):
    if (
        uI and
        validator.is_type(instance, "array") and
        not _utils.uniq(instance)
    ):
        yield ValidationError("%r has non-unique elements" % (instance,))

# ------------------------------------


def uniqueLoItems(validator, uI, instance, schema):
    if (uI and validator.is_type(instance, "array") and not is_unique_item(instance)):
        yield ValidationError("Duplicate items")

def is_unique_item(items):
    uni_by_id = {}
    uni_by_name = {}
    for item in items:
        if 'sku' in item and 'name' in item:
            uni_by_id[item['sku']] = item
            uni_by_name[item['name']] = item
    if len(items) == len(uni_by_id.values()) and len(items) == len(uni_by_name.values()):
        return True
    else:
        return False

def compare(big, small):
    error = False
    if len(big) < len(small):
        error = True
    count_big = 0
    count_small = 0
    for k_1, item_1 in enumerate(big):
        if error is True:
            break
        count_big += item_1["quantity"]
        for k_2, item_2 in enumerate(small):
            if item_1["name"] == item_2['name'] and item_1["sku"] == item_2['sku'] and item_1["price"] == item_2['price']:
                if item_1["quantity"] < item_2["quantity"]:
                    error = True
                else:
                    count_small += item_2["quantity"]
                    small.pop(k_2)
                break
    if count_big <= count_small or len(small) > 0:
        error = True
    return error

def validate_item_field(items, fields):
    errors = []
    for item in items:
        for k in fields:
            if k not in item:
                errors.append('%s is a required property' % k)
    return errors, items


def compareItems(validator, uI, instance, schema):
    error = False
    errs_1, items_1 = validate_item_field(list(uI['items_1']), uI['fields'])
    errs_2, items_2 = validate_item_field(list(uI['items_2']), uI['fields'])
    if errs_1:
        yield ValidationError(';'.join(errs_1))
        return
    if errs_2:
        yield ValidationError(';'.join(errs_2))
        return

    if uI['operator'] == '>':
        error = compare(items_1, items_2)

    elif uI['operator'] == '<':
        error = compare(items_2, items_1)
    else:
        if len(items_1) != len(items_2):
            error = True
        count_items_1 = 0
        count_items_2 = 0
        for k_1, item_1 in enumerate(items_1):
            if error is True:
                break
            count_items_1 += item_1["quantity"]
            for k_2, item_2 in enumerate(items_2):
                if item_1["name"] == item_2['name'] and item_1["sku"] == item_2['sku'] and item_1["price"] == item_2['price']:
                    if item_1["quantity"] != item_2["quantity"]:
                        error = True
                    else:
                        count_items_2 += item_2["quantity"]
                        items_2.pop(k_2)
                    break
        if count_items_1 != count_items_2 or len(items_2) > 0:
            error = True
    if error is True:
        yield ValidationError("Items compare failed")

def compareAddress(validator, uI, instance, schema):
    items_1 = dict(uI['items_1'])
    items_2 = dict(uI['items_2'])
    for f in uI['fields']:
        if items_1[f] != items_2[f]:
            yield ValidationError("Address compare failed")
            break

def get_items_total_price(validator, items):
    items_total = 0
    for item in items:
        if 'price' in item and 'quantity' in item and validator.is_type(item['price'], "number") and validator.is_type(item['quantity'], "number"):
            items_total += item['price'] * item['quantity']
    return items_total


def validatePaidAmount(validator, uI, instance, schema):
    result = False
    if 'payments' in uI and 'paidAmount' in uI:
        payments = uI['payments']
        paidAmount = uI['paidAmount']
        if check_int_or_float(paidAmount):
            transaction_amount = 0
            for payment in payments:
                if 'transactionData' in payment and 'amount' in payment['transactionData'] and check_int_or_float(payment['transactionData']['amount']):
                    transaction_amount += float(payment['transactionData']['amount'])
            if float(paidAmount) != transaction_amount:
                yield ValidationError(uI['err_msg'] if 'err_msg' in uI else 'Validate PaidAmount failed')

def calculateAndCompare(validator, uI, instance, schema):
    if 'operation' in uI and uI['operation']:
        calcResult = None
        if 'compareValue' in uI:
            compareValue = uI['compareValue']
        else:
            compareValue = instance
        try:
            calcResult = eval(uI['operation'])
        except:
            yield ValidationError('calculateAndCompare - operation error')
            return

        if check_int_or_float(compareValue) and check_int_or_float(calcResult):
            try:

                if float(compareValue) != float(calcResult):
                    yield ValidationError(uI['err_msg'] if 'err_msg' in uI else 'calculateAndCompare failed')
            except:
                yield ValidationError('calculateAndCompare - error in compare')
        else:
            yield ValidationError('calculateAndCompare - compareValue or calcResult is not number')

def check_int_or_float(number):
    if isinstance(number, int) or isinstance(number, float):
        return True
    else:
        try:
            number = float(number)
        except ValueError:
            return False
        except TypeError:
            return False
    return False
# ----------------------------------------


def pattern(validator, patrn, instance, schema):
    if (
        validator.is_type(instance, "string") and
        not re.search(patrn, instance)
    ):
        yield ValidationError("%r does not match %r" % (instance, patrn))


def format(validator, format, instance, schema):
    if validator.format_checker is not None:
        try:
            validator.format_checker.check(instance, format)
        except FormatError as error:
            yield ValidationError(error.message, cause=error.cause)


def minLength(validator, mL, instance, schema):
    if validator.is_type(instance, "string") and len(instance) < mL:
        yield ValidationError("%r is too short" % (instance,))


def maxLength(validator, mL, instance, schema):
    if validator.is_type(instance, "string") and len(instance) > mL:
        yield ValidationError("%r is too long" % (instance,))


def dependencies(validator, dependencies, instance, schema):
    if not validator.is_type(instance, "object"):
        return

    for property, dependency in iteritems(dependencies):
        if property not in instance:
            continue

        if validator.is_type(dependency, "object"):
            for error in validator.descend(
                instance, dependency, schema_path=property,
            ):
                yield error
        else:
            dependencies = _utils.ensure_list(dependency)
            for dependency in dependencies:
                if dependency not in instance:
                    yield ValidationError(
                        "%r is a dependency of %r" % (dependency, property)
                    )


def enum(validator, enums, instance, schema):
    if instance not in enums:
        yield ValidationError("%r is not one of %r" % (instance, enums))


def ref(validator, ref, instance, schema):
    resolve = getattr(validator.resolver, "resolve", None)
    if resolve is None:
        with validator.resolver.resolving(ref) as resolved:
            for error in validator.descend(instance, resolved):
                yield error
    else:
        scope, resolved = validator.resolver.resolve(ref)
        validator.resolver.push_scope(scope)

        try:
            for error in validator.descend(instance, resolved):
                yield error
        finally:
            validator.resolver.pop_scope()


def type_draft3(validator, types, instance, schema):
    types = _utils.ensure_list(types)

    all_errors = []
    for index, type in enumerate(types):
        if type == "any":
            return
        if validator.is_type(type, "object"):
            errors = list(validator.descend(instance, type, schema_path=index))
            if not errors:
                return
            all_errors.extend(errors)
        else:
            if validator.is_type(instance, type):
                return
    else:
        yield ValidationError(
            _utils.types_msg(instance, types), context=all_errors,
        )


def properties_draft3(validator, properties, instance, schema):
    if not validator.is_type(instance, "object"):
        return

    for property, subschema in iteritems(properties):
        if property in instance:
            for error in validator.descend(
                instance[property],
                subschema,
                path=property,
                schema_path=property,
            ):
                yield error
        elif subschema.get("required", False):
            error = ValidationError("%r is a required property" % property)
            error._set(
                validator="required",
                validator_value=subschema["required"],
                instance=instance,
                schema=schema,
            )
            error.path.appendleft(property)
            error.schema_path.extend([property, "required"])
            yield error


def disallow_draft3(validator, disallow, instance, schema):
    for disallowed in _utils.ensure_list(disallow):
        if validator.is_valid(instance, {"type": [disallowed]}):
            yield ValidationError(
                "%r is disallowed for %r" % (disallowed, instance)
            )


def extends_draft3(validator, extends, instance, schema):
    if validator.is_type(extends, "object"):
        for error in validator.descend(instance, extends):
            yield error
        return
    for index, subschema in enumerate(extends):
        for error in validator.descend(instance, subschema, schema_path=index):
            yield error


def type_draft4(validator, types, instance, schema):
    types = _utils.ensure_list(types)

    if not any(validator.is_type(instance, type) for type in types):
        yield ValidationError(_utils.types_msg(instance, types))


def properties_draft4(validator, properties, instance, schema):
    if not validator.is_type(instance, "object"):
        return

    for property, subschema in iteritems(properties):
        if property in instance:
            for error in validator.descend(
                instance[property],
                subschema,
                path=property,
                schema_path=property,
            ):
                yield error


def required_draft4(validator, required, instance, schema):
    if not validator.is_type(instance, "object"):
        return
    for property in required:
        if property not in instance:
            yield ValidationError("%r is a required property" % property)


def minProperties_draft4(validator, mP, instance, schema):
    if validator.is_type(instance, "object") and len(instance) < mP:
        yield ValidationError(
            "%r does not have enough properties" % (instance,)
        )


def maxProperties_draft4(validator, mP, instance, schema):
    if not validator.is_type(instance, "object"):
        return
    if validator.is_type(instance, "object") and len(instance) > mP:
        yield ValidationError("%r has too many properties" % (instance,))


def allOf_draft4(validator, allOf, instance, schema):
    for index, subschema in enumerate(allOf):
        err_list = []
        for error in validator.descend(instance, subschema, schema_path=index):
            err_list.append(error)
        if err_list:
            if "err_msg" in subschema:
                yield ValidationError(subschema['err_msg'])
            else:
                for err in err_list:
                    yield err


def oneOf_draft4(validator, oneOf, instance, schema):
    subschemas = enumerate(oneOf)
    all_errors = []
    for index, subschema in subschemas:
        errs = list(validator.descend(instance, subschema, schema_path=index))
        if not errs:
            first_valid = subschema
            break
        for err in errs:
            all_errors.append(subschema['err_msg'] if 'err_msg' in subschema else "%s: %s" % (".".join(err.path), err.message))
    else:
        yield ValidationError(
            schema['err_msg'] if 'err_msg' in schema else 'oneOf clause invalid: ' + '; '.join(all_errors)
        )

    more_valid = [s for i, s in subschemas if validator.is_valid(instance, s)]
    if more_valid:
        more_valid.append(first_valid)
        reprs = ", ".join(repr(schema) for schema in more_valid)
        yield ValidationError(
            s['err_msg'] if 'err_msg' in s else 'oneOf clause invalid: ' + reprs
        )


def anyOf_draft4(validator, anyOf, instance, schema):
    all_errors = []
    for index, subschema in enumerate(anyOf):
        errs = list(validator.descend(instance, subschema, schema_path=index))
        if not errs:
            break
        for err in errs:
            all_errors.append("%s: %s" % (".".join(err.path), err.message))
    else:
        yield ValidationError(
            schema['err_msg'] if 'err_msg' in schema else 'anyOf clause invalid: ' + '; '.join(all_errors)
        )


def not_draft4(validator, not_schema, instance, schema):
    if validator.is_valid(instance, not_schema):
        yield ValidationError(not_schema['err_msg'] if 'err_msg' in not_schema else "%r is not allowed for %r" % (not_schema, instance))
