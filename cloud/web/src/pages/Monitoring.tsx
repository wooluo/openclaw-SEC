/**
 * Monitoring Page
 * System monitoring and analysis
 */

import React, { useState, useEffect } from 'react'
import { Card, Row, Col, Statistic, Progress, Spin } from 'antd'
import {
  ArrowUpOutlined,
  ArrowDownOutlined,
  ThunderboltOutlined,
  DatabaseOutlined,
  GlobalOutlined,
  SafetyOutlined,
} from '@ant-design/icons'
import ReactECharts from 'echarts-for-react'
import dayjs from 'dayjs'
import api from '@/services/api'

const Monitoring = () => {
  const [loading, setLoading] = useState(true)
  const [systemMetrics, setSystemMetrics] = useState<any>(null)
  const [securityMetrics, setSecurityMetrics] = useState<any>(null)
  const [cpuData, setCpuData] = useState<any[]>([])
  const [memoryData, setMemoryData] = useState<any[]>([])

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 10000)
    return () => clearInterval(interval)
  }, [])

  const fetchData = async () => {
    try {
      const [sys, sec, cpu, mem] = await Promise.all([
        api.getSystemMetrics(),
        api.getSecurityMetrics(),
        api.getCPUTimeSeries(1),
        api.getMemoryTimeSeries(1),
      ])

      setSystemMetrics(sys)
      setSecurityMetrics(sec)
      setCpuData(cpu.data || [])
      setMemoryData(mem.data || [])
    } catch (error) {
      console.error('Failed to fetch monitoring data:', error)
    } finally {
      setLoading(false)
    }
  }

  const getGaugeOption = (value: number, title: string, color: string) => ({
    series: [
      {
        type: 'gauge',
        startAngle: 180,
        endAngle: 0,
        min: 0,
        max: 100,
        splitNumber: 10,
        axisLine: {
          lineStyle: {
            width: 15,
            color: [
              [0.3, '#52c41a'],
              [0.7, '#ffa940'],
              [1, '#ff4d4f'],
            ],
          },
        },
        pointer: { icon: 'path://M12.8,0.7l12,40.1H8.3l12-40.1L12.8,0.7z', length: '12', offsetCenter: [0, '60%'] },
        axisTick: { length: 12, lineStyle: { color: 'auto', width: 2 } },
        splitLine: { length: 20, lineStyle: { color: 'auto', width: 5 } },
        axisLabel: { color: 'inherit' },
        detail: {
          valueAnimation: true,
          formatter: '{value}%',
          color: 'inherit',
          fontSize: 20,
          offsetCenter: [0, '70%'],
        },
        title: {
          offsetCenter: [0, '90%'],
          fontSize: 14,
        },
        data: [{ value, name: title }],
      },
    ],
  })

  const getTrafficOption = () => ({
    title: { text: '网络流量' },
    tooltip: { trigger: 'axis' },
    legend: { data: ['发送', '接收'] },
    xAxis: {
      type: 'category',
      data: cpuData.map((d) => dayjs(d.timestamp).format('HH:mm:ss')),
    },
    yAxis: { type: 'value', name: '字节' },
    series: [
      {
        name: '发送',
        type: 'line',
        smooth: true,
        data: cpuData.map((d) => d.value * 1024),
        itemStyle: { color: '#1890ff' },
      },
      {
        name: '接收',
        type: 'line',
        smooth: true,
        data: memoryData.map((d) => d.value * 1024),
        itemStyle: { color: '#52c41a' },
      },
    ],
    grid: { left: 50, right: 20, bottom: 30, top: 30 },
  })

  if (loading || !systemMetrics) {
    return (
      <div style={{ textAlign: 'center', padding: '100px 0' }}>
        <Spin size="large" />
      </div>
    )
  }

  return (
    <div>
      {/* System Metrics */}
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="CPU使用率"
              value={systemMetrics.cpu_percent}
              precision={1}
              suffix="%"
              prefix={<ThunderboltOutlined />}
            />
            <Progress
              percent={systemMetrics.cpu_percent}
              strokeColor={systemMetrics.cpu_percent > 80 ? '#ff4d4f' : '#52c41a'}
              showInfo={false}
              style={{ marginTop: 8 }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="内存使用率"
              value={systemMetrics.memory_percent}
              precision={1}
              suffix="%"
              prefix={<DatabaseOutlined />}
            />
            <Progress
              percent={systemMetrics.memory_percent}
              strokeColor={systemMetrics.memory_percent > 80 ? '#ff4d4f' : '#52c41a'}
              showInfo={false}
              style={{ marginTop: 8 }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="磁盘使用率"
              value={systemMetrics.disk_percent}
              precision={1}
              suffix="%"
              prefix={<DatabaseOutlined />}
            />
            <Progress
              percent={systemMetrics.disk_percent}
              strokeColor={systemMetrics.disk_percent > 80 ? '#ff4d4f' : '#52c41a'}
              showInfo={false}
              style={{ marginTop: 8 }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="活跃连接"
              value={systemMetrics.active_connections}
              prefix={<GlobalOutlined />}
            />
          </Card>
        </Col>
      </Row>

      {/* Charts */}
      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col xs={24} lg={12}>
          <Card title="CPU使用率 (实时)">
            <ReactECharts option={getGaugeOption(systemMetrics.cpu_percent, 'CPU', '#1890ff')} style={{ height: 300 }} />
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card title="内存使用率 (实时)">
            <ReactECharts option={getGaugeOption(systemMetrics.memory_percent, 'Memory', '#52c41a')} style={{ height: 300 }} />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col xs={24}>
          <Card title="网络流量监控">
            <ReactECharts option={getTrafficOption()} style={{ height: 350 }} />
          </Card>
        </Col>
      </Row>

      {/* Security Summary */}
      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col xs={24}>
          <Card title="安全概览" extra={<SafetyOutlined />}>
            <Row gutter={[24, 16]}>
              <Col span={6}>
                <Statistic
                  title="总扫描数"
                  value={securityMetrics.total_scans}
                  prefix={<SafetyOutlined />}
                />
              </Col>
              <Col span={6}>
                <Statistic
                  title="威胁检测"
                  value={securityMetrics.threats_detected}
                  valueStyle={{ color: securityMetrics.threats_detected > 0 ? '#ff4d4f' : '#52c41a' }}
                />
              </Col>
              <Col span={6}>
                <Statistic
                  title="告警生成"
                  value={securityMetrics.alerts_generated}
                />
              </Col>
              <Col span={6}>
                <Statistic
                  title="检测率"
                  value={(securityMetrics.detection_rate * 100).toFixed(2)}
                  suffix="%"
                  valueStyle={{ color: '#1890ff' }}
                />
              </Col>
            </Row>
          </Card>
        </Col>
      </Row>
    </div>
  )
}

export default Monitoring
