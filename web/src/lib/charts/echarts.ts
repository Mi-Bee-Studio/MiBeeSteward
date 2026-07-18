/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
 *
 * This file is part of MiBee Steward, distributed under the GNU Affero General
 * Public License v3.0 or later. You may use, modify, and redistribute it under
 * those terms; see LICENSE for the full text. A commercial license is available
 * for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
 */

import * as echarts from 'echarts/core';
import {
	GaugeChart,
	LineChart,
	BarChart,
	PieChart,
	ScatterChart,
	GraphChart,
	TreeChart
} from 'echarts/charts';
import {
	TitleComponent,
	TooltipComponent,
	GridComponent,
	LegendComponent,
	VisualMapComponent
} from 'echarts/components';
import { CanvasRenderer } from 'echarts/renderers';

echarts.use([
	GaugeChart,
	LineChart,
	BarChart,
	PieChart,
	ScatterChart,
	GraphChart,
	TreeChart,
	TitleComponent,
	TooltipComponent,
	GridComponent,
	LegendComponent,
	VisualMapComponent,
	CanvasRenderer
]);

export { echarts };
export type { ECharts, EChartsOption } from 'echarts/core';
