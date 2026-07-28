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

// Only the chart/component modules actually used by the app are registered
// here (tree-shaking by usage — echarts/core ships just the core). Before
// adding a new chart type or option feature, check whether its module is
// registered below; an unregistered component silently renders nothing.
//
// Commonly-needed-but-currently-unused modules (intentionally NOT registered to
// keep the bundle lean — add the import + echarts.use() entry when a chart
// first needs one):
//   - DatasetComponent       (option.dataset source piping)
//   - DataZoomComponent      (zoom/pan sliders on large series)
//   - MarkLineComponent      (option.series.markLine reference lines)
//   - MarkAreaComponent      (option.series.markArea shaded regions)
//   - PolarComponent         (polar/bar-polar coordinates)
//   - GeoComponent           (map/geo coordinates)
//   - CalendarComponent      (calendar heatmap coordinates)
//   - RadarComponent          (radar coordinates)
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
