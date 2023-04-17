// https://github.com/panva/jose/blob/main/src/lib/secs.ts

const minute = 60;
const hour = minute * 60;
const day = hour * 24;
const week = day * 7;
const year = day * 365.25;

const REGEX =
	/^(\d+|\d+\.\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)$/i;

const convert = (value: number, unit: string): number => {
	switch (unit) {
		case 'sec':
		case 'secs':
		case 'second':
		case 'seconds':
		case 's':
			return Math.round(value);
		case 'minute':
		case 'minutes':
		case 'min':
		case 'mins':
		case 'm':
			return Math.round(value * minute);
		case 'hour':
		case 'hours':
		case 'hr':
		case 'hrs':
		case 'h':
			return Math.round(value * hour);
		case 'day':
		case 'days':
		case 'd':
			return Math.round(value * day);
		case 'week':
		case 'weeks':
		case 'w':
			return Math.round(value * week);
		// years matched
		default:
			return Math.round(value * year);
	}
};

export default (str: string | number): Date => {
	if (typeof str === 'number') {
		return new Date(Date.now() + str * 1000);
	}

	const matched = REGEX.exec(str);

	if (!matched) {
		throw new TypeError('Invalid time period format');
	}

	const value = parseFloat(matched[1]);
	const unit = matched[2].toLowerCase();

	const seconds = convert(value, unit);

	return new Date(Date.now() + seconds * 1000);
};
