/**
 * Dashboard Page
 * Main dashboard with statistics and charts
 */

import React, { useState, useEffect } from 'react'
import { Row, Col, Card, Statistic, Progress, Spin } from 'antd'
import {
  ArrowUpOutlined,
  ArrowDownOutlined,
  ShieldOutlined,
  AlertOutlined,
  FileTextOutlined,
  BugOutlined,
} from '@ant-design/icons'
import ReactECharts from 'echarts-for-react'
import dayjs from 'dayjs'
import api, { wsService } from '@/services/api'

const Dashboard = () => {
  const [loading, setLoading] = useState(true)
  const [dashboardData, setDashboardData] = useState<any>(null)
  const [cpuData, setCpuData] = useState<any[]>([])
  const [memoryData, setMemoryData] = useState<any[]>([])

  useEffect(() => {
    fetchDashboardData()
    fetchTimeSeriesData()

    // Subscribe to real-time updates
    const unsubscribe = wsService.subscribe('dashboard_update', (data) => {
      setDashboardData(data)
    })

    wsService.connect()

    return () => {
      unsubscribe()
      wsService.disconnect()
    }
  }, [])

  const fetchDashboardData = async () => {
    try {
      const data = await api.getDashboard()
      setDashboardData(data)
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error)
    } finally {
      setLoading(false)
    }
  }

  const fetchTimeSeriesData = async () => {
    try {
      const [cpu, memory] = await Promise.all([
        api.getCPUTimeSeries(24),
        api.getMemoryTimeSeries(24),
      ])

      setCpuData(cpu.data || [])
      setMemoryData(memory.data || [])
    } catch (error) {
      console.error('Failed to fetch time series data:', error)
    }
  }

  const getCPUOption = () => ({
    title: { text: 'CPU 使用率' },
    tooltip: { trigger: 'axis' },
    xAxis: {
      type: 'category',
      data: cpuData.map((d) => dayjs(d.timestamp).format('HH:mm')),
    },
    yAxis: { type: 'value', max: 100, name: '%' },
    series: [
      {
        name: 'CPU',
        type: 'line',
        smooth: true,
        data: cpuData.map((d) => d.value),
        itemStyle: { color: '#1890ff' },
        areaStyle: { opacity: 0.3 },
      },
    ],
    grid: { left: 50, right: 20, bottom: 30, top: 30 },
  })

  const getMemoryOption = () => ({
    title: { text: '内存使用率' },
    tooltip: { trigger: 'axis' },
    xAxis: {
      type: 'category',
      data: memoryData.map((d) => dayjs(d.timestamp).format('HH:mm')),
    },
    yAxis: { type: 'value', max: 100, name: '%' },
    series: [
      {
        name: 'Memory',
        type: 'line',
        smooth: true,
        data: memoryData.map((d) => d.value),
        itemStyle: { color: '#52c41a' },
        areaStyle: { opacity: 0.3 },
      },
    ],
    grid: { left: 50, right: 20, bottom: 30, top: 30 },
  })

  if (loading || !dashboardData) {
    return (
      <div style={{ textAlign: 'center', padding: '100px 0' }}>
        <Spin size="large" />
      </div>
    )
  }

  const { systemMetrics, securityMetrics, recentAlerts, activeThreats } = dashboardData

  return (
    <div>
      <Row gutter={[16, 16]}>
        {/* System Metrics */}
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="CPU 使用率"
              value={systemMetrics.cpu_percent}
              precision={1}
              suffix="%"
              prefix={<ArrowUpOutlined style={{ color: systemMetrics.cpu_percent > 80 ? '#ff4d4f' : '#52c41a' }} />}
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
              prefix={<ArrowUpOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="活跃连接"
              value={systemMetrics.active_connections}
              prefix={<ShieldOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="运行时间"
              value={Math.floor(systemMetrics.uptime_seconds / 3600)}
              suffix="小时"
              prefix={<ArrowUpOutlined />}
            />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        {/* Security Metrics */}
        <Col xs={24} md={12}>
          <Card title="安全统计" extra={<AlertOutlined />}>
            <Row gutter={[16, 16]}>
              <Col span={12}>
                <Statistic
                  title="扫描总数"
                  value={securityMetrics.total_scans}
                  prefix={<FileTextOutlined />}
                />
              </Col>
              <Col span={12}>
                <Statistic
                  title="检测威胁"
                  value={securityMetrics.threats_detected}
                  valueStyle={{ color: securityMetrics.threats_detected > 0 ? '#ff4d4f' : '#52c41a' }}
                  prefix={<BugOutlined />}
                />
              </Col>
              <Col span={12}>
                <Statistic
                  title="生成告警"
                  value={securityMetrics.alerts_generated}
                  prefix={<AlertOutlined />}
                />
              </Col>
              <Col span={12}>
                <Statistic
                  title="阻断请求"
                  value={securityMetrics.blocked_requests}
                  valueStyle={{ color: '#52c41a' }}
                />
              </Col>
            </Row>
            <div style={{ marginTop: 16 }}>
              <div style={{ marginBottom: 8, display: 'flex', justifyContent: 'space-between' }}>
                <span>检测率</span>
                <span>{(securityMetrics.detection_rate * 100).toFixed(2)}%</span>
              </div>
              <Progress
                percent={securityMetrics.detection_rate * 100}
                strokeColor="#52c41a"
              />
            </div>
          </Card>
        </Col>

        {/* Threat Summary */}
        <Col xs={24} md={12}>
          <Card title="威胁概览">
            <Row gutter={[16, 16]}>
              <Col span={8}>
                <Card className="card-stat">
                  <Statistic
                    title="近期告警"
                    value={recentAlerts}
                    valueStyle={{ color: recentAlerts > 0 ? '#ff7a45' : '#52c41a' }}
                  />
                </Card>
              </Col>
              <Col span={8}>
                <Card className="card-stat">
                  <Statistic
                    title="活跃威胁"
                    value={activeThreats}
                    valueStyle={{ color: activeThreats > 0 ? '#ff4d4f' : '#52c41a' }}
                  />
                </Card>
              </Col>
              <Col span={8}>
                <Card className="card-stat">
                  <Statistic
                    title="已处理"
                    value={securityMetrics.alerts_generated - activeThreats}
                    valueStyle={{ color: '#52c41a' }}
                  />
                </Card>
              </Col>
            </Row>
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        {/* CPU Chart */}
        <Col xs={24} lg={12}>
          <Card title="CPU 使用趋势 (24小时)">
            <ReactECharts option={getCPUOption()} style={{ height: 300 }} />
          </Card>
        </Col>

        {/* Memory Chart */}
        <Col xs={24} lg={12}>
          <Card title="内存使用趋势 (24小时)">
            <ReactECharts option={getMemoryOption()} style={{ height: 300 }} />
          </Card>
        </Col>
      </Row>
    </div>
  )
}

export default Dashboard
